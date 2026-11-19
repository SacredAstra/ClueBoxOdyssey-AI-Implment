import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { expect, test } from 'vitest';
import { parseRegistryHive } from './registry';

const fixtureBytes = readFileSync(resolve(process.cwd(), 'public/fixtures/SOFTWARE.hive'));

function makeHive({
  rootNameCompressed = true,
  subkeyListFormat = 'li',
  riIndexDepth = 1,
  volatileRootSubkey = false,
  extraRootSubkey = false,
} = {}) {
  const buffer = new Uint8Array(8192);
  const view = new DataView(buffer.buffer);
  let nextOffset = 32;
  const cells = new Map();
  const align = (value) => (value + 7) & ~7;
  const allocate = (bodyLength) => {
    const offset = nextOffset;
    const size = align(bodyLength + 4);
    nextOffset += size;
    cells.set(offset, { size, body: new Uint8Array(size - 4) });
    return offset;
  };
  const cellBody = (offset) => cells.get(offset).body;
  const put16 = (offset, position, value) => new DataView(cellBody(offset).buffer).setUint16(position, value, true);
  const put32 = (offset, position, value) => new DataView(cellBody(offset).buffer).setUint32(position, value, true);
  const writeCell = (offset) => {
    const cell = cells.get(offset);
    view.setInt32(4096 + offset, -cell.size, true);
    buffer.set(cell.body, 4096 + offset + 4);
  };
  const encodeUtf16 = (text) => {
    const bytes = new Uint8Array((text.length + 1) * 2);
    for (let index = 0; index < text.length; index += 1) {
      bytes[index * 2] = text.charCodeAt(index) & 0xff;
      bytes[index * 2 + 1] = text.charCodeAt(index) >> 8;
    }
    return bytes;
  };
  const keyDefinitions = [
    { name: 'Software', parentIndex: null },
    { name: 'Microsoft', parentIndex: 0 },
    { name: 'Windows', parentIndex: 1 },
    { name: 'CurrentVersion', parentIndex: 2 },
    { name: 'Run', parentIndex: 3 },
    ...(extraRootSubkey ? [{ name: 'Classes', parentIndex: 0 }] : []),
  ];
  const keys = keyDefinitions.map(({ name, parentIndex }, index) => {
    const compressed = index > 0 || rootNameCompressed;
    return {
      name,
      parentIndex,
      compressed,
      offset: allocate(0x4c + name.length * (compressed ? 1 : 2)),
    };
  });
  const childKeys = keys.map((_, index) => keys.filter((key) => key.parentIndex === index));
  const commandBytes = encodeUtf16('C:\\Temp\\sample.exe\0');
  const dataOffset = allocate(commandBytes.length);
  cellBody(dataOffset).set(commandBytes);
  const valueName = 'Updater';
  const valueOffset = allocate(0x14 + valueName.length);
  const valueListOffset = allocate(8);
  const subkeyLists = keys.map((_, index) => {
    const children = childKeys[index];
    if (!children.length) return 0;
    let listOffset;
    if (subkeyListFormat === 'ri') {
      listOffset = allocate(4 + children.length * 4);
      cellBody(listOffset).set([0x6c, 0x69], 0);
      put16(listOffset, 2, children.length);
      children.forEach((child, childIndex) => put32(listOffset, 4 + childIndex * 4, child.offset));
      let rootOffset = listOffset;
      for (let depth = 0; depth < riIndexDepth; depth += 1) {
        const indexOffset = allocate(8);
        cellBody(indexOffset).set([0x72, 0x69], 0);
        put16(indexOffset, 2, 1);
        put32(indexOffset, 4, rootOffset);
        rootOffset = indexOffset;
      }
      listOffset = rootOffset;
    } else {
      const entrySize = subkeyListFormat === 'li' ? 4 : 8;
      listOffset = allocate(4 + children.length * entrySize);
      const body = cellBody(listOffset);
      body[0] = subkeyListFormat.charCodeAt(0);
      body[1] = subkeyListFormat.charCodeAt(1);
      put16(listOffset, 2, children.length);
      children.forEach((child, childIndex) => put32(listOffset, 4 + childIndex * entrySize, child.offset));
    }
    return listOffset;
  });

  keys.forEach(({ name, offset }, index) => {
    const body = cellBody(offset);
    body.set([0x6e, 0x6b], 0);
    put16(offset, 2, (keys[index].compressed ? 0x20 : 0) | (index === 0 ? 0x04 : 0));
    const childCount = childKeys[index].length;
    put32(offset, 0x14, childCount);
    put32(offset, 0x18, volatileRootSubkey && index === 0 ? 1 : 0);
    put32(offset, 0x1c, childCount ? subkeyLists[index] : 0);
    put32(offset, 0x20, volatileRootSubkey && index === 0 ? 0x80000128 : 0);
    put32(offset, 0x24, name === 'Run' ? 1 : 0);
    put32(offset, 0x28, name === 'Run' ? valueListOffset : 0);
    put16(offset, 0x48, name.length * (keys[index].compressed ? 1 : 2));
    for (let nameIndex = 0; nameIndex < name.length; nameIndex += 1) {
      body[0x4c + nameIndex * (keys[index].compressed ? 1 : 2)] = name.charCodeAt(nameIndex) & 0xff;
      if (!keys[index].compressed) {
        body[0x4d + nameIndex * 2] = name.charCodeAt(nameIndex) >> 8;
      }
    }
  });

  const valueBody = cellBody(valueOffset);
  valueBody.set([0x76, 0x6b], 0);
  put16(valueOffset, 2, valueName.length);
  put32(valueOffset, 4, commandBytes.length);
  put32(valueOffset, 8, dataOffset);
  put32(valueOffset, 0x0c, 1);
  put16(valueOffset, 0x10, 1);
  for (let index = 0; index < valueName.length; index += 1) valueBody[0x14 + index] = valueName.charCodeAt(index);

  put32(valueListOffset, 0, valueOffset);
  cells.forEach((_, offset) => writeCell(offset));
  buffer.set([0x72, 0x65, 0x67, 0x66], 0);
  view.setUint32(0x24, keys[0].offset, true);
  view.setUint32(0x28, 4096, true);
  buffer.set([0x68, 0x62, 0x69, 0x6e], 4096);
  view.setUint32(4104, 4096, true);
  return buffer;
}

test('parses an offline REGF hive and extracts startup command artifacts', () => {
  const result = parseRegistryHive(makeHive(), 'SOFTWARE');

  expect(result).toMatchObject({
    format: 'Windows Registry Hive (REGF)',
    hiveType: 'SOFTWARE',
    keyCount: 5,
    warnings: [],
    artifacts: [{
      type: 'Startup command',
      keyPath: 'Software\\Microsoft\\Windows\\CurrentVersion\\Run',
      values: [{
        name: 'Updater',
        type: 1,
        data: 'C:\\Temp\\sample.exe',
      }],
    }],
  });
  expect(Date.parse(result.parsedAt)).not.toBeNaN();
});

test('parses valid uncompressed UTF-16LE key names', () => {
  const result = parseRegistryHive(makeHive({ rootNameCompressed: false }), 'SOFTWARE');

  expect(result.keyCount).toBe(5);
  expect(result.artifacts[0].keyPath).toBe('Software\\Microsoft\\Windows\\CurrentVersion\\Run');
});

test.each(['li', 'lf', 'lh', 'ri'])(
  'traverses multi-level and sibling keys using %s indexes and stable or volatile subkey fields',
  (subkeyListFormat) => {
    const result = parseRegistryHive(makeHive({
      subkeyListFormat,
      riIndexDepth: 20,
      volatileRootSubkey: true,
      extraRootSubkey: true,
    }), 'SOFTWARE');

    expect(result.keyCount).toBe(6);
    expect(result.warnings).toEqual([
      'Registry key "Software" has 1 volatile subkey(s) referenced by HCELL_INDEX 0x80000128 in nk+0x20. '
      + 'Volatile storage is not present in the offline hive file, so these subkeys cannot be analyzed from this evidence.',
    ]);
    expect(result.artifacts[0]).toMatchObject({
      type: 'Startup command',
      keyPath: 'Software\\Microsoft\\Windows\\CurrentVersion\\Run',
    });
  },
);

test.each(['li', 'lf', 'lh', 'ri'])(
  'rejects a volatile HCELL_INDEX in a stable %s list without masking it',
  (subkeyListFormat) => {
    const malformedHive = makeHive({ subkeyListFormat });
    const view = new DataView(malformedHive.buffer);
    const rootOffset = view.getUint32(0x24, true);
    const rootCellStart = 4096 + rootOffset + 4;
    const listOffset = view.getUint32(rootCellStart + 0x1c, true);
    const invalidChildOffset = 0x80000128;
    view.setUint32(4096 + listOffset + 8, invalidChildOffset, true);

    expect(() => parseRegistryHive(malformedHive)).toThrow(
      new RegExp(`stable subkey-list offset field.*volatile ${subkeyListFormat} .*0x${invalidChildOffset.toString(16)}`),
    );
  },
);

test('rejects a volatile cell index in the stable subkey-list field without masking it', () => {
  const malformedHive = makeHive();
  const view = new DataView(malformedHive.buffer);
  const rootOffset = view.getUint32(0x24, true);
  const rootCellStart = 4096 + rootOffset + 4;
  const invalidListOffset = 0x80000128;
  view.setUint32(rootCellStart + 0x1c, invalidListOffset, true);

  expect(() => parseRegistryHive(malformedHive)).toThrow(
    new RegExp(
      `Registry key "Software".*stable subkey-list field nk\\+0x1c contains a volatile `
      + `cell index 0x${invalidListOffset.toString(16)}`,
    ),
  );
});

test('analyzes stable root subkeys and reports volatile subkeys unavailable in the saved hive', () => {
  const malformedHive = makeHive({ volatileRootSubkey: true });
  const result = parseRegistryHive(malformedHive, 'SOFTWARE');

  expect(result.keyCount).toBe(5);
  expect(result.artifacts[0].keyPath).toBe('Software\\Microsoft\\Windows\\CurrentVersion\\Run');
  expect(result.warnings).toContain(
    'Registry key "Software" has 1 volatile subkey(s) referenced by HCELL_INDEX 0x80000128 in nk+0x20. '
    + 'Volatile storage is not present in the offline hive file, so these subkeys cannot be analyzed from this evidence.',
  );
});

test('reports cyclic ri subkey indexes instead of silently stopping traversal', () => {
  const malformedHive = makeHive({ subkeyListFormat: 'ri' });
  const view = new DataView(malformedHive.buffer);
  const rootOffset = view.getUint32(0x24, true);
  const rootCellStart = 4096 + rootOffset + 4;
  const listOffset = view.getUint32(rootCellStart + 0x1c, true);
  view.setUint32(4096 + listOffset + 8, listOffset, true);

  expect(() => parseRegistryHive(malformedHive)).toThrow(/subkey index contains a cycle/);
});

test('reports an out-of-range subkey-list cell with its type, offset, request, and bounds', () => {
  const malformedHive = makeHive();
  const view = new DataView(malformedHive.buffer);
  const rootOffset = view.getUint32(0x24, true);
  const rootCellStart = 4096 + rootOffset + 4;
  const invalidListOffset = 0x7ffffff0;
  view.setUint32(rootCellStart + 0x1c, invalidListOffset, true);

  expect(() => parseRegistryHive(malformedHive)).toThrow(
    new RegExp(
      `out-of-range cell header: cell offset 0x${invalidListOffset.toString(16)}, `
      + 'requested length 4 bytes; available bounds are \\[0x1000, 0x2000\\)',
    ),
  );
});

test('does not follow a subkey-list offset when the corresponding count is zero', () => {
  const hive = makeHive();
  const view = new DataView(hive.buffer);
  const rootOffset = view.getUint32(0x24, true);
  const rootCellStart = 4096 + rootOffset + 4;
  view.setUint32(rootCellStart + 0x14, 0, true);
  view.setUint32(rootCellStart + 0x1c, 0xfffffff0, true);

  expect(parseRegistryHive(hive)).toMatchObject({
    keyCount: 1,
    warnings: [],
    artifacts: [],
  });
});

test('rejects a subkey-index cell that crosses its hive-bin boundary', () => {
  const malformedHive = makeHive();
  const view = new DataView(malformedHive.buffer);
  const rootOffset = view.getUint32(0x24, true);
  const rootCellStart = 4096 + rootOffset + 4;
  const listOffset = view.getUint32(rootCellStart + 0x1c, true);
  view.setInt32(4096 + listOffset, -0x2000, true);

  expect(() => parseRegistryHive(malformedHive)).toThrow(
    new RegExp(`invalid cell at hive offset 0x${listOffset.toString(16)}: declared cell length 8192 bytes`),
  );
});

test('rejects files that are not valid offline registry hives', () => {
  expect(() => parseRegistryHive(new Uint8Array(8192))).toThrow(/not a supported offline Windows registry hive/);
  const malformedHive = makeHive();
  malformedHive[4096] = 0;
  expect(() => parseRegistryHive(malformedHive)).toThrow(/no valid first hive bin/);
  expect(() => parseRegistryHive('invalid input')).toThrow(/ArrayBuffer or byte array/);
});

test('reports declared key names that do not fit in their cells', () => {
  const malformedHive = makeHive();
  const view = new DataView(malformedHive.buffer);
  const rootOffset = view.getUint32(0x24, true);
  const rootCellStart = 4096 + rootOffset + 4;
  view.setUint16(rootCellStart + 0x48, 0xffff, true);

  expect(() => parseRegistryHive(malformedHive)).toThrow(
    /declared name length \(65535 bytes\) exceeds the \d+ name bytes available in its cell/,
  );
});

test('reports the key and value-list cell when the declared value count exceeds the parser limit', () => {
  const malformedHive = makeHive();
  const view = new DataView(malformedHive.buffer);
  const rootOffset = view.getUint32(0x24, true);
  const rootCellStart = 4096 + rootOffset + 4;
  const declaredValueCount = 20_306;
  view.setUint32(rootCellStart + 0x24, declaredValueCount, true);

  expect(() => parseRegistryHive(malformedHive)).toThrow(
    new RegExp(
      `Registry key "Software" at key cell offset 0x${rootOffset.toString(16)} `
      + `declares ${declaredValueCount} values, exceeding the parser limit of 10000; `
      + 'its value-list cell offset is 0x0',
    ),
  );
});

test('reports declared value count and available space when a value-list cell is too small', () => {
  const malformedHive = makeHive();
  const view = new DataView(malformedHive.buffer);
  const rootOffset = view.getUint32(0x24, true);
  const rootCellStart = 4096 + rootOffset + 4;
  const valueListOffset = view.getUint32(rootCellStart + 0x1c, true);
  view.setUint32(rootCellStart + 0x24, 4, true);
  view.setUint32(rootCellStart + 0x28, valueListOffset, true);

  expect(() => parseRegistryHive(malformedHive)).toThrow(
    new RegExp(
      `Registry key "Software" at key cell offset 0x${rootOffset.toString(16)} `
      + `declares 4 values, requiring 16 bytes in value-list cell 0x${valueListOffset.toString(16)}, `
      + 'which contains 12 bytes',
    ),
  );
});

test('reports the key, declared count, and invalid value-list cell offset', () => {
  const malformedHive = makeHive();
  const view = new DataView(malformedHive.buffer);
  const rootOffset = view.getUint32(0x24, true);
  const rootCellStart = 4096 + rootOffset + 4;
  const invalidListOffset = 0xfffffff0;
  view.setUint32(rootCellStart + 0x24, 1, true);
  view.setUint32(rootCellStart + 0x28, invalidListOffset, true);

  expect(() => parseRegistryHive(malformedHive)).toThrow(
    new RegExp(
      `Registry key "Software" at key cell offset 0x${rootOffset.toString(16)} `
      + `declares 1 values, but value-list cell offset 0x${invalidListOffset.toString(16)} `
      + 'is outside the hive or is not a valid allocated cell',
    ),
  );
});

test('analyzes the downloadable synthetic SOFTWARE hive and verifies its SHA-256', () => {
  const sha256 = createHash('sha256').update(fixtureBytes).digest('hex');
  const view = new DataView(fixtureBytes.buffer, fixtureBytes.byteOffset, fixtureBytes.byteLength);
  let headerChecksum = 0;
  for (let offset = 0; offset < 0x1fc; offset += 4) {
    headerChecksum = (headerChecksum ^ view.getUint32(offset, true)) >>> 0;
  }
  const result = parseRegistryHive(fixtureBytes, 'SOFTWARE.hive');

  expect(sha256).toBe('46716f39c075f7c55c7c731370f71e39e21f7a7edc968724ba2a04bc24c24e3e');
  expect(view.getUint32(0x1fc, true)).toBe(headerChecksum);
  expect(result).toMatchObject({
    format: 'Windows Registry Hive (REGF)',
    hiveType: 'SOFTWARE',
    keyCount: 8,
    warnings: [],
    artifacts: [
      {
        type: 'Startup command',
        keyPath: 'Software\\Microsoft\\Windows\\CurrentVersion\\Run',
        values: [
          { name: 'ForensiAIUpdater', type: 1, data: '%ProgramFiles%\\ForensiAI\\Updater.exe /background' },
          { name: 'ExampleBackup', type: 1, data: 'C:\\Program Files\\Example Backup\\backup.exe /silent' },
        ],
      },
      {
        type: 'Startup command',
        keyPath: 'Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
        values: [{ name: 'ForensiAISetup', type: 1, data: 'C:\\ForensiAI-Test\\finish-setup.exe' }],
      },
      {
        type: 'Installed application',
        keyPath: 'Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\ForensiAI Test Utility',
        values: [
          { name: 'DisplayName', type: 1, data: 'ForensiAI Test Utility' },
          { name: 'DisplayVersion', type: 1, data: '1.2.3' },
          { name: 'Publisher', type: 1, data: 'ForensiAI Sample Data' },
          { name: 'InstallDate', type: 1, data: '20261109' },
        ],
      },
    ],
  });
});
