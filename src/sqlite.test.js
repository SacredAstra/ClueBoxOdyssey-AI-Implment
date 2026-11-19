import { expect, test, vi } from 'vitest';
import initSqlJs from 'sql.js';
import { analyzeSqlite } from './sqlite';

const { wasmPath } = vi.hoisted(() => ({
  wasmPath: `${process.cwd()}/node_modules/sql.js/dist/sql-wasm.wasm`,
}));

vi.mock('sql.js/dist/sql-wasm.wasm?url', () => ({
  default: wasmPath,
}));

const SQL = initSqlJs({ locateFile: () => wasmPath });

async function createFixture() {
  const SQLModule = await SQL;
  const database = new SQLModule.Database();
  database.run(`
    PRAGMA user_version = 12;
    CREATE TABLE events (
      id INTEGER PRIMARY KEY,
      created_at TEXT NOT NULL,
      updated_time INTEGER,
      title TEXT DEFAULT 'sample',
      attachment BLOB
    );
    INSERT INTO events (created_at, updated_time, title, attachment)
    VALUES ('2025-03-04 05:06:07', 1741064767, 'harmless test row', X'0102FF');
    INSERT INTO events (created_at, updated_time, title)
    VALUES ('not a date', NULL, 'second harmless row');
    CREATE VIEW event_titles AS SELECT id, title FROM events;
  `);
  const bytes = database.export();
  database.close();
  return bytes;
}

test('lists SQLite schemas, bounded records, views, and recognized timestamp fields', async () => {
  const bytes = await createFixture();
  const original = bytes.slice();
  const report = await analyzeSqlite(bytes, 'temporary-sample.sqlite');
  const events = report.tables.find((table) => table.name === 'events');

  expect(bytes).toEqual(original);
  expect(report).toMatchObject({
    format: 'SQLite Database',
    filename: 'temporary-sample.sqlite',
    userVersion: 12,
    tableCount: 1,
    viewCount: 1,
    recordCount: 4,
    recordsTruncated: false,
  });
  expect(events.schemaSql).toContain('CREATE TABLE events');
  expect(events.columns).toContainEqual(expect.objectContaining({
    name: 'id',
    type: 'INTEGER',
    primaryKey: true,
  }));
  expect(events.records[0]).toMatchObject({
    created_at: '2025-03-04 05:06:07',
    updated_time: 1741064767,
    title: 'harmless test row',
    attachment: { type: 'blob', byteLength: 3, hexPreview: '0102ff', truncated: false },
  });
  expect(events.timestampFields).toEqual([
    expect.objectContaining({
      column: 'created_at',
      hasRecognizedValues: true,
      examples: [expect.objectContaining({ iso: '2025-03-04T05:06:07.000Z', reason: 'Date/time text' })],
    }),
    expect.objectContaining({
      column: 'updated_time',
      hasRecognizedValues: true,
      examples: [expect.objectContaining({ iso: '2025-03-04T05:06:07.000Z', reason: 'Unix seconds' })],
    }),
  ]);
  expect(report.tables.find((table) => table.name === 'event_titles').type).toBe('view');
});

test('initializes SQLite WebAssembly and reads tables from a valid .db evidence file', async () => {
  const bytes = await createFixture();
  const report = await analyzeSqlite(bytes, 'synthetic-evidence.db');
  const events = report.tables.find((table) => table.name === 'events');

  expect(report).toMatchObject({
    format: 'SQLite Database',
    filename: 'synthetic-evidence.db',
    tableCount: 1,
  });
  expect(events.records).toHaveLength(2);
  expect(events.records[0]).toMatchObject({
    id: 1,
    title: 'harmless test row',
  });
});

test('rejects invalid and over-limit inputs without changing the source buffer', async () => {
  await expect(analyzeSqlite(new Uint8Array(20))).rejects.toThrow(/not a supported SQLite 3 database/);
  await expect(analyzeSqlite('not a database')).rejects.toThrow(/ArrayBuffer or byte array/);
});
