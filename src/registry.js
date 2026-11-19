const HIVE_HEADER_SIZE = 4096;
const MAX_KEY_DEPTH = 64;
const MAX_SUBKEY_INDEX_DEPTH = 64;
const MAX_KEYS = 100_000;
const MAX_VALUES_PER_KEY = 10_000;
const MAX_VALUE_BYTES = 16 * 1024 * 1024;
const MAX_ARTIFACTS = 2_000;
const HCELL_VOLATILE = 0x80000000;
const HCELL_NIL = 0xffffffff;
const ROT13 = (value) => value.replace(/[a-z]/gi, (character) => String.fromCharCode(
  character.charCodeAt(0) + (character.toLowerCase() <= 'm' ? 13 : -13),
));

function toBytes(input) {
  if (input instanceof Uint8Array) return input;
  if (ArrayBuffer.isView(input)) return new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
  if (input instanceof ArrayBuffer || Object.prototype.toString.call(input) === '[object ArrayBuffer]') return new Uint8Array(input);
  throw new TypeError('Registry hive input must be an ArrayBuffer or byte array.');
}

class RegistryHive {
  constructor(input) {
    this.bytes = toBytes(input);
    this.view = new DataView(this.bytes.buffer, this.bytes.byteOffset, this.bytes.byteLength);
    this.keyCount = 0;
    this.keys = [];
    this.warnings = [];
    if (this.bytes.length < HIVE_HEADER_SIZE + 32 || this.ascii(0, 4) !== 'regf') {
      throw new Error('The evidence is not a supported offline Windows registry hive (REGF).');
    }
    if (this.ascii(HIVE_HEADER_SIZE, 4) !== 'hbin') {
      throw new Error('The registry hive has no valid first hive bin.');
    }
    this.hiveBinsLength = this.u32(0x28);
    if (!this.hiveBinsLength || this.hiveBinsLength > this.bytes.length - HIVE_HEADER_SIZE) {
      throw new Error(
        `The registry hive declares ${this.hiveBinsLength} hive-bin bytes, but only `
        + `${Math.max(0, this.bytes.length - HIVE_HEADER_SIZE)} bytes are available after its header.`,
      );
    }
    this.hiveBins = this.readHiveBins();
    const rootOffset = this.u32(0x24);
    if (!rootOffset || rootOffset >= this.hiveBinsLength) {
      throw new Error('The registry hive root key offset is invalid.');
    }
    this.rootOffset = rootOffset;
  }

  readHiveBins() {
    const bins = [];
    const hiveEnd = HIVE_HEADER_SIZE + this.hiveBinsLength;
    let relativeOffset = 0;
    while (relativeOffset < this.hiveBinsLength) {
      const binOffset = HIVE_HEADER_SIZE + relativeOffset;
      if (binOffset + 0x20 > hiveEnd) {
        throw new Error(
          `The registry hive-bin header at file offset 0x${binOffset.toString(16)} is truncated; `
          + `requested length 32 bytes, available bounds are [0x${binOffset.toString(16)}, `
          + `0x${hiveEnd.toString(16)}).`,
        );
      }
      if (this.ascii(binOffset, 4) !== 'hbin') {
        throw new Error(`The registry hive bin at file offset 0x${binOffset.toString(16)} has an invalid signature.`);
      }
      const declaredOffset = this.u32(binOffset + 4);
      const binSize = this.u32(binOffset + 8);
      if (declaredOffset !== relativeOffset || binSize < 0x1000
        || binSize % 0x1000 !== 0 || relativeOffset + binSize > this.hiveBinsLength) {
        throw new Error(
          `The registry hive bin at file offset 0x${binOffset.toString(16)} declares relative offset `
          + `0x${declaredOffset.toString(16)} and size ${binSize} bytes, inconsistent with available `
          + `hive-bin bounds [0x${relativeOffset.toString(16)}, 0x${this.hiveBinsLength.toString(16)}).`,
        );
      }
      bins.push({ start: relativeOffset, end: relativeOffset + binSize });
      relativeOffset += binSize;
    }
    if (relativeOffset !== this.hiveBinsLength) {
      throw new Error('The registry hive-bin sizes do not match the length declared in the hive header.');
    }
    return bins;
  }

  bounds(offset, length, structure = 'structure', cellOffset = null) {
    if (!Number.isSafeInteger(offset) || !Number.isSafeInteger(length)
      || offset < 0 || length < 0 || offset + length > this.bytes.length) {
      const availableStart = Math.max(0, Math.min(offset, this.bytes.length));
      const availableEnd = this.bytes.length;
      const cellDescription = cellOffset === null ? '' : ` in cell at hive offset 0x${cellOffset.toString(16)}`;
      throw new Error(
        `The registry hive contains an out-of-range ${structure}${cellDescription}: `
        + `file offset 0x${Number.isFinite(offset) ? Math.trunc(offset).toString(16) : 'invalid'}, `
        + `requested length ${length} bytes; available bounds are [0x${availableStart.toString(16)}, `
        + `0x${availableEnd.toString(16)}) (${Math.max(0, availableEnd - availableStart)} bytes).`,
      );
    }
  }

  u16(offset, structure = '16-bit field', cellOffset = null) {
    this.bounds(offset, 2, structure, cellOffset);
    return this.view.getUint16(offset, true);
  }

  u32(offset, structure = '32-bit field', cellOffset = null) {
    this.bounds(offset, 4, structure, cellOffset);
    return this.view.getUint32(offset, true);
  }

  ascii(offset, length, structure = 'signature', cellOffset = null) {
    this.bounds(offset, length, structure, cellOffset);
    let result = '';
    for (let index = 0; index < length; index += 1) result += String.fromCharCode(this.bytes[offset + index]);
    return result;
  }

  cell(relativeOffset, invalidCellMessage, reference = '') {
    const physicalOffset = HIVE_HEADER_SIZE + relativeOffset;
    const referenceDescription = reference ? ` Referenced by ${reference}.` : '';
    if (!Number.isSafeInteger(relativeOffset) || relativeOffset < 0
      || !Number.isSafeInteger(physicalOffset)) {
      throw new Error(
        `${invalidCellMessage || `The registry cell at hive offset 0x${String(relativeOffset)} has an invalid offset.`}`
        + referenceDescription,
      );
    }
    const bin = this.hiveBins.find((candidate) => (
      relativeOffset >= candidate.start + 0x20 && relativeOffset + 4 <= candidate.end
    ));
    if (!bin) {
      const containingBin = this.hiveBins.find((candidate) => (
        relativeOffset >= candidate.start && relativeOffset < candidate.end
      ));
      const start = containingBin ? containingBin.start : 0;
      const end = containingBin ? containingBin.end : this.hiveBinsLength;
      const availableStart = HIVE_HEADER_SIZE + start;
      const availableEnd = HIVE_HEADER_SIZE + end;
      throw new Error(
        `${invalidCellMessage ? `${invalidCellMessage}; ` : 'The registry hive contains an out-of-range cell header: '}`
        + `cell offset 0x${relativeOffset.toString(16)}, requested length 4 bytes; available bounds are `
        + `[0x${availableStart.toString(16)}, 0x${availableEnd.toString(16)}).${referenceDescription}`,
      );
    }
    const signedLength = this.view.getInt32(physicalOffset, true);
    const length = Math.abs(signedLength);
    if (signedLength >= 0 || length < 8 || relativeOffset + length > bin.end) {
      throw new Error(
        invalidCellMessage
          || `The registry hive contains an invalid cell at hive offset 0x${relativeOffset.toString(16)}: `
          + `declared cell length ${length} bytes; available bounds are `
          + `[0x${(HIVE_HEADER_SIZE + relativeOffset).toString(16)}, `
          + `0x${(HIVE_HEADER_SIZE + bin.end).toString(16)}).${referenceDescription}`,
      );
    }
    return { start: physicalOffset + 4, end: physicalOffset + length };
  }

  utf16(offset, length, cellOffset = null) {
    this.bounds(offset, length, 'UTF-16LE string', cellOffset);
    return new TextDecoder('utf-16le', { fatal: false }).decode(this.bytes.subarray(offset, offset + length)).replace(/\0+$/, '');
  }

  cellName(relativeOffset) {
    const cell = this.cell(relativeOffset);
    if (this.ascii(cell.start, 2, 'key-node signature', relativeOffset) !== 'nk') {
      throw new Error('A registry subkey does not reference a key node.');
    }
    if (cell.start + 0x4c > cell.end) throw new Error('A registry key node is truncated.');
    const flags = this.u16(cell.start + 2, 'key-node flags', relativeOffset);
    const nameLength = this.u16(cell.start + 0x48, 'key-name length', relativeOffset);
    const nameOffset = cell.start + 0x4c;
    const availableNameBytes = cell.end - nameOffset;
    if (nameLength > availableNameBytes) {
      throw new Error(
        `The registry hive contains a key node at cell offset 0x${relativeOffset.toString(16)} `
        + `whose declared name length (${nameLength} bytes) exceeds the ${availableNameBytes} `
        + 'name bytes available in its cell.',
      );
    }
    if (!(flags & 0x20) && nameLength % 2 !== 0) {
      throw new Error(`The registry key name at cell offset 0x${relativeOffset.toString(16)} has an invalid UTF-16 byte length.`);
    }
    return (flags & 0x20)
      ? this.ascii(nameOffset, nameLength, 'key name', relativeOffset)
      : this.utf16(nameOffset, nameLength, relativeOffset);
  }

  subkeyOffsets(listOffset, depth = 0, ancestors = new Set(), reference = '') {
    if (!listOffset) return [];
    if (depth >= MAX_SUBKEY_INDEX_DEPTH) {
      throw new Error(`The registry subkey index exceeds the ${MAX_SUBKEY_INDEX_DEPTH}-level depth limit.`);
    }
    if (ancestors.has(listOffset)) {
      throw new Error(`The registry subkey index contains a cycle at cell offset 0x${listOffset.toString(16)}.`);
    }
    const nextAncestors = new Set(ancestors).add(listOffset);
    const cell = this.cell(listOffset, null, reference);
    const signature = this.ascii(cell.start, 2, 'subkey-index signature', listOffset);
    const count = this.u16(cell.start + 2, 'subkey-index entry count', listOffset);
    if (count > MAX_KEYS) throw new Error('The registry hive subkey index is too large.');
    const offsets = [];
    if (signature === 'ri') {
      if (cell.start + 4 + count * 4 > cell.end) throw new Error('The registry subkey index is truncated.');
      for (let index = 0; index < count; index += 1) {
        const indexOffset = this.u32(cell.start + 4 + index * 4, 'ri subkey-index entry', listOffset);
        if (indexOffset === HCELL_NIL || indexOffset & HCELL_VOLATILE) {
          throw new Error(
            `The ${reference} contains ${indexOffset === HCELL_NIL ? 'a null' : 'a volatile'} `
            + `ri index reference 0x${indexOffset.toString(16)} at entry ${index}; `
            + 'a stable on-disk subkey index was expected.',
          );
        }
        const children = this.subkeyOffsets(
          indexOffset,
          depth + 1,
          nextAncestors,
          `${reference}; ri entry ${index} in index cell 0x${listOffset.toString(16)}`,
        );
        if (offsets.length + children.length > MAX_KEYS) {
          throw new Error('The registry hive subkey index is too large.');
        }
        for (const childOffset of children) offsets.push(childOffset);
      }
      return offsets;
    }
    if (signature !== 'li' && signature !== 'lf' && signature !== 'lh') {
      throw new Error(
        `The registry subkey index at cell offset 0x${listOffset.toString(16)} `
        + `has an unsupported signature "${signature}".`,
      );
    }
    const entrySize = signature === 'li' ? 4 : 8;
    if (cell.start + 4 + count * entrySize > cell.end) throw new Error('The registry subkey index is truncated.');
    for (let index = 0; index < count; index += 1) {
      const childOffset = this.u32(
        cell.start + 4 + index * entrySize,
        `${signature} subkey-index entry`,
        listOffset,
      );
      if (childOffset === HCELL_NIL || childOffset & HCELL_VOLATILE) {
        throw new Error(
          `The ${reference} contains ${childOffset === HCELL_NIL ? 'a null' : 'a volatile'} `
          + `${signature} child reference 0x${childOffset.toString(16)} at entry ${index}; `
          + 'a stable on-disk key cell was expected.',
        );
      }
      this.cell(
        childOffset,
        null,
        `${reference}; ${signature} entry ${index} in index cell 0x${listOffset.toString(16)}`,
      );
      offsets.push(childOffset);
    }
    return offsets;
  }

  valueData(relativeOffset) {
    const cell = this.cell(relativeOffset);
    if (this.ascii(cell.start, 2, 'value-cell signature', relativeOffset) !== 'vk') {
      throw new Error('A registry value list does not reference a value cell.');
    }
    if (cell.start + 0x14 > cell.end) throw new Error('A registry value cell is truncated.');
    const nameLength = this.u16(cell.start + 2, 'value-name length', relativeOffset);
    const encodedLength = this.u32(cell.start + 4, 'value-data length', relativeOffset);
    const dataLength = encodedLength & 0x7fffffff;
    const dataOffset = this.u32(cell.start + 8, 'value-data cell offset', relativeOffset);
    const type = this.u32(cell.start + 0x0c, 'value type', relativeOffset);
    const flags = this.u16(cell.start + 0x10, 'value flags', relativeOffset);
    const nameByteLength = flags & 1 ? nameLength : nameLength * 2;
    if (cell.start + 0x14 + nameByteLength > cell.end) {
      throw new Error(
        `The registry value name at cell offset 0x${relativeOffset.toString(16)} declares `
        + `${nameByteLength} bytes; available bounds are [0x${cell.start.toString(16)}, `
        + `0x${cell.end.toString(16)}).`,
      );
    }
    const valueName = nameLength
      ? ((flags & 1)
        ? this.ascii(cell.start + 0x14, nameLength, 'value name', relativeOffset)
        : this.utf16(cell.start + 0x14, nameLength, relativeOffset))
      : '(Default)';
    if (dataLength > MAX_VALUE_BYTES) throw new Error(`Registry value "${valueName}" exceeds the parser size limit.`);
    let bytes;
    if (encodedLength & 0x80000000) {
      if (dataLength > 4) throw new Error(`Registry value "${valueName}" has an invalid inline data length.`);
      bytes = new Uint8Array(4);
      new DataView(bytes.buffer).setUint32(0, dataOffset, true);
      bytes = bytes.subarray(0, dataLength);
    } else if (dataLength === 0) {
      bytes = new Uint8Array();
    } else {
      const dataCell = this.cell(dataOffset);
      if (dataCell.start + dataLength > dataCell.end) {
        throw new Error(
          `Registry value "${valueName}" at data cell offset 0x${dataOffset.toString(16)} `
          + `requests ${dataLength} bytes; available bounds are [0x${dataCell.start.toString(16)}, `
          + `0x${dataCell.end.toString(16)}).`,
        );
      }
      bytes = this.bytes.slice(dataCell.start, dataCell.start + dataLength);
    }
    return { name: valueName, type, data: this.decodeValue(type, bytes) };
  }

  decodeValue(type, bytes) {
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    if (type === 1 || type === 2 || type === 6) return new TextDecoder('utf-16le').decode(bytes).replace(/\0+$/, '');
    if (type === 7) return new TextDecoder('utf-16le').decode(bytes).split('\0').filter(Boolean);
    if (type === 4 && bytes.length >= 4) return view.getUint32(0, true);
    if (type === 5 && bytes.length >= 4) return view.getUint32(0, false);
    if (type === 11 && bytes.length >= 8) return view.getBigUint64(0, true).toString();
    return {
      byteLength: bytes.length,
      hexPreview: Array.from(bytes.subarray(0, 64), (byte) => byte.toString(16).padStart(2, '0')).join(''),
      truncated: bytes.length > 64,
    };
  }

  valuesAt(valueCount, valueListOffset, keyOffset, keyPath) {
    if (valueCount > MAX_VALUES_PER_KEY) {
      throw new Error(
        `Registry key "${keyPath}" at key cell offset 0x${keyOffset.toString(16)} `
        + `declares ${valueCount} values, exceeding the parser limit of ${MAX_VALUES_PER_KEY}; `
        + `its value-list cell offset is 0x${valueListOffset.toString(16)}.`,
      );
    }
    if (!valueCount) return [];
    const invalidListMessage = `Registry key "${keyPath}" at key cell offset 0x${keyOffset.toString(16)} `
      + `declares ${valueCount} values, but value-list cell offset 0x${valueListOffset.toString(16)} `
      + 'is outside the hive or is not a valid allocated cell.';
    const list = this.cell(valueListOffset, invalidListMessage);
    const availableBytes = list.end - list.start;
    const requiredBytes = valueCount * 4;
    if (requiredBytes > availableBytes) {
      throw new Error(
        `Registry key "${keyPath}" at key cell offset 0x${keyOffset.toString(16)} `
        + `declares ${valueCount} values, requiring ${requiredBytes} bytes in value-list cell `
        + `0x${valueListOffset.toString(16)}, which contains ${availableBytes} bytes.`,
      );
    }
    return Array.from({ length: valueCount }, (_, index) => this.valueData(this.u32(list.start + index * 4)));
  }

  readKey(relativeOffset, parentPath = '', depth = 0, ancestors = new Set()) {
    if (depth > MAX_KEY_DEPTH) {
      this.warnings.push(`Key traversal stopped at the ${MAX_KEY_DEPTH}-level depth limit.`);
      return;
    }
    if (this.keyCount >= MAX_KEYS) {
      this.warnings.push(`Key traversal stopped at the ${MAX_KEYS}-key safety limit.`);
      return;
    }
    if (ancestors.has(relativeOffset)) throw new Error('The registry hive contains a cyclic key tree.');
    this.keyCount += 1;
    const cell = this.cell(relativeOffset);
    if (this.ascii(cell.start, 2) !== 'nk') throw new Error('The registry hive root does not reference a key node.');
    if (cell.start + 0x4c > cell.end) throw new Error('A registry key node is truncated.');
    const name = this.cellName(relativeOffset);
    const path = parentPath ? `${parentPath}\\${name}` : name;
    const stableSubkeyCount = this.u32(cell.start + 0x14);
    const volatileSubkeyCount = this.u32(cell.start + 0x18);
    const stableSubkeyListOffset = this.u32(cell.start + 0x1c);
    const volatileSubkeyListOffset = this.u32(cell.start + 0x20);
    const valueCount = this.u32(cell.start + 0x24);
    const valueListOffset = this.u32(cell.start + 0x28);
    const values = this.valuesAt(valueCount, valueListOffset, relativeOffset, path);
    this.keys.push({ path, values });
    const subkeyCount = stableSubkeyCount + volatileSubkeyCount;
    if (subkeyCount > MAX_KEYS) throw new Error(`Registry key "${path}" declares too many subkeys.`);
    if (stableSubkeyCount && !stableSubkeyListOffset) {
      throw new Error(`Registry key "${path}" declares ${stableSubkeyCount} stable subkeys but has a null subkey-list offset.`);
    }
    if (stableSubkeyCount && (stableSubkeyListOffset === HCELL_NIL
      || stableSubkeyListOffset & HCELL_VOLATILE)) {
      throw new Error(
        `Registry key "${path}" declares ${stableSubkeyCount} stable subkeys, but stable subkey-list `
        + `field nk+0x1c contains ${stableSubkeyListOffset === HCELL_NIL ? 'HCELL_NIL' : 'a volatile'} `
        + `cell index 0x${stableSubkeyListOffset.toString(16)}.`,
      );
    }
    if (volatileSubkeyCount && (!volatileSubkeyListOffset || volatileSubkeyListOffset === HCELL_NIL)) {
      throw new Error(`Registry key "${path}" declares ${volatileSubkeyCount} volatile subkeys but has a null volatile subkey-list offset.`);
    }
    if (volatileSubkeyCount && !(volatileSubkeyListOffset & HCELL_VOLATILE)) {
      throw new Error(
        `Registry key "${path}" declares ${volatileSubkeyCount} volatile subkeys, but volatile subkey-list `
        + `field nk+0x20 contains a stable cell index 0x${volatileSubkeyListOffset.toString(16)}.`,
      );
    }
    const childOffsets = [
      ...(stableSubkeyCount
        ? this.subkeyOffsets(
          stableSubkeyListOffset,
          0,
          new Set(),
          `the stable subkey-list offset field (nk+0x1c) at key cell 0x${relativeOffset.toString(16)} under key "${path}"`,
        )
        : []),
    ];
    if (childOffsets.length !== stableSubkeyCount) {
      throw new Error(
        `Registry key "${path}" declares ${stableSubkeyCount} stable subkeys, `
        + `but its stable subkey index contains ${childOffsets.length} entries.`,
      );
    }
    if (volatileSubkeyCount) {
      this.warnings.push(
        `Registry key "${path}" has ${volatileSubkeyCount} volatile subkey(s) referenced by `
        + `HCELL_INDEX 0x${volatileSubkeyListOffset.toString(16)} in nk+0x20. Volatile storage is `
        + 'not present in the offline hive file, so these subkeys cannot be analyzed from this evidence.',
      );
    }
    const nextAncestors = new Set(ancestors).add(relativeOffset);
    for (const childOffset of childOffsets.slice(0, subkeyCount)) {
      this.readKey(childOffset, path, depth + 1, nextAncestors);
    }
  }

  parse() {
    this.readKey(this.rootOffset);
    return this.keys;
  }
}

function artifact(type, key, values) {
  return { type, keyPath: key.path, values };
}

function extractArtifacts(keys, warnings) {
  const results = [];
  const add = (type, key, values) => {
    if (!values.length) return;
    if (results.length >= MAX_ARTIFACTS) {
      if (!warnings.includes(`Artifact extraction stopped at the ${MAX_ARTIFACTS}-artifact safety limit.`)) {
        warnings.push(`Artifact extraction stopped at the ${MAX_ARTIFACTS}-artifact safety limit.`);
      }
      return;
    }
    results.push(artifact(type, key, values));
  };
  const value = (key, name) => key.values.find((entry) => entry.name.toLowerCase() === name.toLowerCase())?.data;
  const matches = (key, expression) => expression.test(key.path);

  for (const key of keys) {
    if (matches(key, /\\Microsoft\\Windows\\CurrentVersion\\Run(?:Once)?$/i)) {
      add('Startup command', key, key.values);
    }
    if (matches(key, /\\Internet Explorer\\TypedURLs$/i)) {
      add('Typed URL', key, key.values);
    }
    if (matches(key, /\\Explorer\\RecentDocs(?:\\.*)?$/i) && key.values.length) {
      add('Recent documents', key, key.values);
    }
    if (matches(key, /\\UserAssist\\\{[^}]+\}\\Count$/i) && key.values.length) {
      add('UserAssist execution entry', key, key.values.map((entry) => ({
        ...entry,
        name: ROT13(entry.name),
      })));
    }
    if (matches(key, /\\Enum\\USBSTOR(?:\\.*)?$/i)) {
      add('USB storage device', key, key.values);
    }
    if (matches(key, /\\MountedDevices$/i)) {
      add('Mounted device', key, key.values);
    }
    if (matches(key, /\\ControlSet\d{3}\\Services\\[^\\]+$/i)) {
      add('Service configuration', key, key.values.filter((entry) => (
        ['ImagePath', 'DisplayName', 'Start', 'Type', 'ObjectName'].includes(entry.name)
      )));
    }
    if (matches(key, /\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\[^\\]+$/i)) {
      add('User profile', key, key.values.filter((entry) => ['ProfileImagePath', 'Flags', 'State'].includes(entry.name)));
    }
    if (matches(key, /\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\[^\\]+$/i)) {
      add('Installed application', key, key.values.filter((entry) => (
        ['DisplayName', 'DisplayVersion', 'Publisher', 'InstallDate', 'InstallLocation'].includes(entry.name)
      )));
    }
    if (matches(key, /\\Microsoft\\Windows NT\\CurrentVersion$/i)) {
      add('Windows installation', key, key.values.filter((entry) => (
        ['ProductName', 'DisplayVersion', 'CurrentBuild', 'BuildLabEx', 'InstallDate', 'RegisteredOwner'].includes(entry.name)
      )));
    }
  }
  return results;
}

export function parseRegistryHive(input, filename = '') {
  const hive = new RegistryHive(input);
  const keys = hive.parse();
  const path = filename.toLowerCase();
  const hiveType = /(?:^|[\\/])system(?:\.hive)?$/.test(path) ? 'SYSTEM'
    : /(?:^|[\\/])software(?:\.hive)?$/.test(path) ? 'SOFTWARE'
      : /(?:^|[\\/])sam(?:\.hive)?$/.test(path) ? 'SAM'
        : /(?:^|[\\/])security(?:\.hive)?$/.test(path) ? 'SECURITY'
          : /(?:^|[\\/])ntuser\.dat$/.test(path) ? 'NTUSER.DAT'
            : /(?:^|[\\/])usrclass\.dat$/.test(path) ? 'UsrClass.dat' : 'Unknown';
  return {
    format: 'Windows Registry Hive (REGF)',
    hiveType,
    parsedAt: new Date().toISOString(),
    keyCount: hive.keyCount,
    artifacts: extractArtifacts(keys, hive.warnings),
    warnings: hive.warnings,
  };
}
