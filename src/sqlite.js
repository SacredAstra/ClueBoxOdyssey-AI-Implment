import initSqlJs from 'sql.js';
import wasmUrl from 'sql.js/dist/sql-wasm.wasm?url';

const MAX_DATABASE_BYTES = 256 * 1024 * 1024;
const MAX_TABLES = 500;
const MAX_COLUMNS_PER_TABLE = 200;
const MAX_ROWS_PER_TABLE = 200;
const MAX_TOTAL_ROWS = 2_000;
const MAX_TEXT_VALUE_LENGTH = 8_192;
const MAX_BLOB_PREVIEW_BYTES = 64;
const MAX_OUTPUT_CHARACTERS = 5_000_000;
const TIMESTAMP_COLUMN = /(time|date|created|updated|modified|accessed|deleted|installed|lastseen|firstseen|_at$)/i;
let sqlPromise;

function toBytes(input) {
  if (input instanceof Uint8Array) return input;
  if (ArrayBuffer.isView(input)) return new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
  if (input instanceof ArrayBuffer || Object.prototype.toString.call(input) === '[object ArrayBuffer]') return new Uint8Array(input);
  throw new TypeError('SQLite input must be an ArrayBuffer or byte array.');
}

function quoteIdentifier(identifier) {
  return `"${identifier.replaceAll('"', '""')}"`;
}

function normalizeValue(value) {
  if (value instanceof Uint8Array) {
    return {
      type: 'blob',
      byteLength: value.length,
      hexPreview: Array.from(value.subarray(0, MAX_BLOB_PREVIEW_BYTES), (byte) => byte.toString(16).padStart(2, '0')).join(''),
      truncated: value.length > MAX_BLOB_PREVIEW_BYTES,
    };
  }
  if (typeof value === 'string' && value.length > MAX_TEXT_VALUE_LENGTH) {
    return { type: 'text', value: value.slice(0, MAX_TEXT_VALUE_LENGTH), truncated: true };
  }
  return value;
}

function isoIfTimestamp(value) {
  let milliseconds;
  let reason;
  if (typeof value === 'number' && Number.isFinite(value)) {
    if (Math.abs(value) >= 1e12 && Math.abs(value) < 1e14) {
      milliseconds = value;
      reason = 'Unix milliseconds';
    } else if (Math.abs(value) >= 1e9 && Math.abs(value) < 1e11) {
      milliseconds = value * 1000;
      reason = 'Unix seconds';
    }
  } else if (typeof value === 'string') {
    const trimmed = value.trim();
    if (/^-?\d{10,13}$/.test(trimmed)) {
      return isoIfTimestamp(Number(trimmed));
    }
    if (/^\d{4}-\d{2}-\d{2}(?:[ T].*)?$/.test(trimmed)) {
      const parsed = Date.parse(trimmed);
      if (Number.isFinite(parsed)) {
        milliseconds = parsed;
        reason = 'Date/time text';
      }
    }
  }
  if (!Number.isFinite(milliseconds)) return null;
  const date = new Date(milliseconds);
  if (Number.isNaN(date.getTime()) || date.getUTCFullYear() < 1900 || date.getUTCFullYear() > 2200) return null;
  return { iso: date.toISOString(), reason };
}

function getTimestampFields(columns, rows) {
  return columns.filter((column) => TIMESTAMP_COLUMN.test(column.name)).map((column) => {
    const examples = [];
    for (const row of rows) {
      const value = row[column.name];
      if (value === null || value === undefined) continue;
      const converted = isoIfTimestamp(value);
      if (converted && !examples.some((example) => example.raw === value)) {
        examples.push({ raw: value, ...converted });
      }
      if (examples.length >= 5) break;
    }
    return {
      column: column.name,
      declaredType: column.type,
      examples,
      hasRecognizedValues: examples.length > 0,
    };
  });
}

function execSingleValue(database, sql) {
  const results = database.exec(sql);
  return results[0]?.values[0]?.[0] ?? 0;
}

function getSqlModule() {
  if (!sqlPromise) {
    sqlPromise = initSqlJs({ locateFile: () => wasmUrl }).catch((error) => {
      sqlPromise = undefined;
      throw new Error(
        'SQLite WebAssembly could not be loaded. Reload the page and try again. If the problem persists, contact support.',
        { cause: error },
      );
    });
  }
  return sqlPromise;
}

export async function analyzeSqlite(input, filename = '') {
  const bytes = toBytes(input);
  if (bytes.length > MAX_DATABASE_BYTES) throw new Error('The SQLite database exceeds the 256 MiB local analysis limit.');
  if (bytes.length < 16 || new TextDecoder().decode(bytes.subarray(0, 16)) !== 'SQLite format 3\0') {
    throw new Error('The evidence is not a supported SQLite 3 database.');
  }

  const SQLModule = await getSqlModule();
  let database;
  try {
    database = new SQLModule.Database(bytes);
    database.exec('PRAGMA query_only = ON;');
    const version = execSingleValue(database, 'PRAGMA user_version;');
    const objects = database.exec(
      "SELECT type, name, tbl_name, sql FROM sqlite_master WHERE type IN ('table', 'view') AND name NOT LIKE 'sqlite_%' ORDER BY type, name LIMIT 501;",
    )[0]?.values || [];
    if (objects.length > MAX_TABLES) throw new Error(`The database contains more than the ${MAX_TABLES} supported tables/views.`);

    let remainingRows = MAX_TOTAL_ROWS;
    let outputCharacters = 0;
    let truncated = false;
    const warnings = [];
    const tables = [];
    for (const [objectType, name, tableName, sql] of objects) {
      const object = {
        name,
        type: objectType,
        tableName,
        schemaSql: typeof sql === 'string' ? sql.slice(0, MAX_TEXT_VALUE_LENGTH) : null,
        columns: [],
        timestampFields: [],
        records: [],
        recordLimitReached: false,
      };
      try {
        const pragma = database.exec(`PRAGMA table_xinfo(${quoteIdentifier(name)});`)[0]?.values || [];
        object.columns = pragma.slice(0, MAX_COLUMNS_PER_TABLE).map(([, columnName, declaredType, notNull, defaultValue, primaryKey, hidden]) => ({
          name: columnName,
          type: declaredType || '',
          notNull: notNull === 1,
          defaultValue: normalizeValue(defaultValue),
          primaryKey: primaryKey > 0,
          hidden: hidden > 0,
        }));
        object.columnsTruncated = pragma.length > MAX_COLUMNS_PER_TABLE;
        if (object.columnsTruncated) {
          truncated = true;
          warnings.push(`Columns in ${objectType} "${name}" were limited to the first ${MAX_COLUMNS_PER_TABLE}.`);
        }
        const limit = Math.min(MAX_ROWS_PER_TABLE, remainingRows);
        if (limit > 0) {
          const selection = object.columns.map((column) => quoteIdentifier(column.name)).join(', ');
          const statement = database.prepare(`SELECT ${selection} FROM ${quoteIdentifier(name)} LIMIT ${limit + 1};`);
          try {
            const columnNames = statement.getColumnNames();
            while (statement.step()) {
              const values = statement.get();
              if (object.records.length === limit) {
                object.recordLimitReached = true;
                truncated = true;
                break;
              }
              const normalizedRow = Object.fromEntries(columnNames.map((columnName, index) => [
                columnName,
                normalizeValue(values[index]),
              ]));
              const rowCharacters = JSON.stringify(normalizedRow).length;
              if (outputCharacters + rowCharacters > MAX_OUTPUT_CHARACTERS) {
                object.recordLimitReached = true;
                truncated = true;
                warnings.push(`Record output was capped at ${MAX_OUTPUT_CHARACTERS.toLocaleString()} characters.`);
                break;
              }
              object.records.push(normalizedRow);
              outputCharacters += rowCharacters;
              remainingRows -= 1;
            }
          } finally {
            statement.free();
          }
        } else {
          object.recordLimitReached = true;
          truncated = true;
        }
        object.timestampFields = getTimestampFields(object.columns, object.records);
      } catch (error) {
        warnings.push(`Could not read ${objectType} "${name}": ${error.message}`);
      }
      tables.push(object);
    }
    if (remainingRows === 0 && tables.length > 0) {
      warnings.push(`Record output was capped at ${MAX_TOTAL_ROWS.toLocaleString()} rows across the database.`);
    }
    if (truncated) warnings.push('Some table records were omitted due to the configured per-table or total output limits.');
    return {
      format: 'SQLite Database',
      filename,
      analyzedAt: new Date().toISOString(),
      userVersion: version,
      tableCount: tables.filter((table) => table.type === 'table').length,
      viewCount: tables.filter((table) => table.type === 'view').length,
      recordCount: tables.reduce((count, table) => count + table.records.length, 0),
      recordsTruncated: truncated,
      tables,
      warnings,
    };
  } catch (error) {
    if (error instanceof Error && /SQLite|database|file is not a database|malformed/i.test(error.message)) throw error;
    throw new Error(`SQLite database analysis failed: ${error.message}`);
  } finally {
    database?.close();
  }
}
