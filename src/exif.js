const TYPE_SIZES = {
  1: 1,
  2: 1,
  3: 2,
  4: 4,
  5: 8,
  6: 1,
  7: 1,
  8: 2,
  9: 4,
  10: 8,
  11: 4,
  12: 8,
};

const ORIENTATIONS = {
  1: 'Top-left',
  2: 'Top-right (mirrored)',
  3: 'Bottom-right (rotated 180°)',
  4: 'Bottom-left (mirrored)',
  5: 'Left-top (mirrored)',
  6: 'Right-top (rotated 90° clockwise)',
  7: 'Right-bottom (mirrored)',
  8: 'Left-bottom (rotated 90° counterclockwise)',
};

function decodeAscii(bytes) {
  return new TextDecoder('ascii').decode(bytes).replace(/\0+$/, '').trim();
}

function parseTiff(bytes, start) {
  if (start + 8 > bytes.length) return null;
  const byteOrder = String.fromCharCode(bytes[start], bytes[start + 1]);
  if (byteOrder !== 'II' && byteOrder !== 'MM') return null;
  const littleEndian = byteOrder === 'II';
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const u16 = (offset) => {
    if (offset < start || offset + 2 > bytes.length) throw new RangeError('Invalid TIFF offset');
    return view.getUint16(offset, littleEndian);
  };
  const u32 = (offset) => {
    if (offset < start || offset + 4 > bytes.length) throw new RangeError('Invalid TIFF offset');
    return view.getUint32(offset, littleEndian);
  };
  if (u16(start + 2) !== 42) return null;

  const readIfd = (offset) => {
    const ifdOffset = start + offset;
    const entryCount = u16(ifdOffset);
    if (entryCount > 512 || ifdOffset + 2 + entryCount * 12 + 4 > bytes.length) {
      throw new RangeError('Invalid TIFF directory');
    }
    const tags = new Map();
    for (let index = 0; index < entryCount; index += 1) {
      const entryOffset = ifdOffset + 2 + index * 12;
      const tag = u16(entryOffset);
      const type = u16(entryOffset + 2);
      const count = u32(entryOffset + 4);
      const typeSize = TYPE_SIZES[type];
      if (!typeSize || count > 4096) continue;
      const byteLength = typeSize * count;
      const valueOffset = byteLength <= 4 ? entryOffset + 8 : start + u32(entryOffset + 8);
      if (valueOffset < start || valueOffset + byteLength > bytes.length) continue;
      const readUnsigned = (position) => {
        if (type === 1 || type === 6 || type === 7) return view.getUint8(position);
        if (type === 3) return view.getUint16(position, littleEndian);
        if (type === 4) return view.getUint32(position, littleEndian);
        if (type === 8) return view.getInt16(position, littleEndian);
        if (type === 9) return view.getInt32(position, littleEndian);
        return null;
      };
      let value;
      if (type === 2) {
        value = decodeAscii(bytes.subarray(valueOffset, valueOffset + byteLength));
      } else if (type === 5 || type === 10) {
        value = Array.from({ length: count }, (_, item) => {
          const numerator = type === 5 ? u32(valueOffset + item * 8) : view.getInt32(valueOffset + item * 8, littleEndian);
          const denominator = type === 5 ? u32(valueOffset + item * 8 + 4) : view.getInt32(valueOffset + item * 8 + 4, littleEndian);
          return denominator === 0 ? null : numerator / denominator;
        });
      } else if (type === 11) {
        value = Array.from({ length: count }, (_, item) => view.getFloat32(valueOffset + item * 4, littleEndian));
      } else if (type === 12) {
        value = Array.from({ length: count }, (_, item) => view.getFloat64(valueOffset + item * 8, littleEndian));
      } else {
        value = Array.from({ length: count }, (_, item) => readUnsigned(valueOffset + item * typeSize));
      }
      tags.set(tag, count === 1 && Array.isArray(value) ? value[0] : value);
    }
    return tags;
  };

  const root = readIfd(u32(start + 4));
  const exif = root.has(0x8769) ? readIfd(root.get(0x8769)) : new Map();
  const gps = root.has(0x8825) ? readIfd(root.get(0x8825)) : new Map();
  return { root, exif, gps };
}

function gpsDecimal(coordinate, reference) {
  if (!Array.isArray(coordinate) || coordinate.length < 3 || !reference) return undefined;
  const [degrees, minutes, seconds] = coordinate;
  if (![degrees, minutes, seconds].every(Number.isFinite)) return undefined;
  const decimal = degrees + minutes / 60 + seconds / 3600;
  return reference === 'S' || reference === 'W' ? -decimal : decimal;
}

function appendValue(result, name, value) {
  if (typeof value === 'string' && value) result[name] = value;
  else if (typeof value === 'number' && Number.isFinite(value)) result[name] = value;
}

function normalizeExif({ root, exif, gps }) {
  const result = {};
  appendValue(result, 'cameraMake', root.get(0x010f));
  appendValue(result, 'cameraModel', root.get(0x0110));
  appendValue(result, 'capturedAt', exif.get(0x9003));
  appendValue(result, 'digitizedAt', exif.get(0x9004));
  appendValue(result, 'modifiedAt', root.get(0x0132));
  appendValue(result, 'software', root.get(0x0131));
  appendValue(result, 'lensModel', exif.get(0xa434));
  appendValue(result, 'imageWidth', exif.get(0xa002) ?? root.get(0x0100));
  appendValue(result, 'imageHeight', exif.get(0xa003) ?? root.get(0x0101));

  const orientation = root.get(0x0112);
  if (ORIENTATIONS[orientation]) result.orientation = ORIENTATIONS[orientation];

  const latitude = gpsDecimal(gps.get(2), gps.get(1));
  const longitude = gpsDecimal(gps.get(4), gps.get(3));
  appendValue(result, 'gpsLatitude', latitude);
  appendValue(result, 'gpsLongitude', longitude);
  const altitude = gps.get(6);
  if (Number.isFinite(altitude)) {
    result.gpsAltitudeMeters = gps.get(5) === 1 ? -altitude : altitude;
  }
  return Object.keys(result).length ? result : null;
}

function findTiffStart(bytes) {
  if (bytes[0] === 0x49 && bytes[1] === 0x49 || bytes[0] === 0x4d && bytes[1] === 0x4d) return 0;
  if (bytes[0] !== 0xff || bytes[1] !== 0xd8) return -1;

  let offset = 2;
  while (offset + 4 <= bytes.length) {
    if (bytes[offset] !== 0xff) return -1;
    while (bytes[offset] === 0xff) offset += 1;
    const marker = bytes[offset];
    offset += 1;
    if (marker === 0xd9 || marker === 0xda) return -1;
    if (marker === 0x01 || marker >= 0xd0 && marker <= 0xd7) continue;
    if (offset + 2 > bytes.length) return -1;
    const segmentLength = bytes[offset] * 256 + bytes[offset + 1];
    if (segmentLength < 2 || offset + segmentLength > bytes.length) return -1;
    const payloadOffset = offset + 2;
    if (
      marker === 0xe1
      && segmentLength >= 8
      && bytes[payloadOffset] === 0x45
      && bytes[payloadOffset + 1] === 0x78
      && bytes[payloadOffset + 2] === 0x69
      && bytes[payloadOffset + 3] === 0x66
      && bytes[payloadOffset + 4] === 0
      && bytes[payloadOffset + 5] === 0
    ) return payloadOffset + 6;
    offset += segmentLength;
  }
  return -1;
}

export function extractExifMetadata(input) {
  const isArrayBuffer = input instanceof ArrayBuffer
    || Object.prototype.toString.call(input) === '[object ArrayBuffer]';
  const bytes = input instanceof Uint8Array
    ? input
    : ArrayBuffer.isView(input)
      ? new Uint8Array(input.buffer, input.byteOffset, input.byteLength)
      : isArrayBuffer
        ? new Uint8Array(input)
        : null;
  if (!bytes) return null;
  const tiffStart = findTiffStart(bytes);
  if (tiffStart < 0) return null;
  try {
    return normalizeExif(parseTiff(bytes, tiffStart));
  } catch {
    return null;
  }
}
