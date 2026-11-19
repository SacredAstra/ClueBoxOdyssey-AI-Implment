import { expect, test } from 'vitest';
import { extractExifMetadata } from './exif';

function createTiff(littleEndian = true) {
  const bytes = new Uint8Array(312);
  const view = new DataView(bytes.buffer);
  const write16 = (offset, value) => view.setUint16(offset, value, littleEndian);
  const write32 = (offset, value) => view.setUint32(offset, value, littleEndian);
  const writeEntry = (offset, tag, type, count, value) => {
    write16(offset, tag);
    write16(offset + 2, type);
    write32(offset + 4, count);
    if (typeof value === 'string') {
      bytes.set([value.charCodeAt(0), 0], offset + 8);
    } else if (count === 1 && type === 3) {
      write16(offset + 8, value);
    } else if (count === 1 && (type === 1 || type === 4)) {
      if (type === 1) bytes[offset + 8] = value;
      else write32(offset + 8, value);
    } else {
      write32(offset + 8, value);
    }
  };
  const writeRational = (offset, numerator, denominator) => {
    write32(offset, numerator);
    write32(offset + 4, denominator);
  };

  bytes.set(littleEndian ? [0x49, 0x49] : [0x4d, 0x4d], 0);
  write16(2, 42);
  write32(4, 8);

  write16(8, 5);
  writeEntry(10, 0x010f, 2, 5, 206);
  writeEntry(22, 0x0110, 2, 8, 211);
  writeEntry(34, 0x0112, 3, 1, 6);
  writeEntry(46, 0x8769, 4, 1, 74);
  writeEntry(58, 0x8825, 4, 1, 128);

  write16(74, 4);
  writeEntry(76, 0x9003, 2, 20, 219);
  writeEntry(88, 0xa434, 2, 11, 239);
  writeEntry(100, 0xa002, 4, 1, 4032);
  writeEntry(112, 0xa003, 4, 1, 3024);

  write16(128, 6);
  writeEntry(130, 1, 2, 2, 'N');
  writeEntry(142, 2, 5, 3, 252);
  writeEntry(154, 3, 2, 2, 'W');
  writeEntry(166, 4, 5, 3, 276);
  writeEntry(178, 5, 1, 1, 1);
  writeEntry(190, 6, 5, 1, 300);

  bytes.set(new TextEncoder().encode('Canon'), 206);
  bytes.set(new TextEncoder().encode('EOS R5'), 211);
  bytes.set(new TextEncoder().encode('2025:03:04 05:06:07\0'), 219);
  bytes.set(new TextEncoder().encode('50mm f/1.8\0'), 239);
  writeRational(252, 37, 1);
  writeRational(260, 48, 1);
  writeRational(268, 0, 1);
  writeRational(276, 122, 1);
  writeRational(284, 15, 1);
  writeRational(292, 0, 1);
  writeRational(300, 123, 10);
  bytes[310] = 0;
  return bytes.subarray(0, 311);
}

function wrapAsJpeg(tiff) {
  const payloadLength = 6 + tiff.length;
  const segmentLength = payloadLength + 2;
  const jpeg = new Uint8Array(4 + segmentLength + 2);
  jpeg.set([0xff, 0xd8, 0xff, 0xe1, segmentLength >> 8, segmentLength & 0xff, 0x45, 0x78, 0x69, 0x66, 0, 0], 0);
  jpeg.set(tiff, 12);
  jpeg.set([0xff, 0xd9], 12 + tiff.length);
  return jpeg;
}

test.each([true, false])('extracts camera, capture, orientation, lens, and GPS fields (littleEndian=%s)', (littleEndian) => {
  const metadata = extractExifMetadata(wrapAsJpeg(createTiff(littleEndian)));

  expect(metadata).toEqual({
    cameraMake: 'Canon',
    cameraModel: 'EOS R5',
    capturedAt: '2025:03:04 05:06:07',
    lensModel: '50mm f/1.8',
    imageWidth: 4032,
    imageHeight: 3024,
    orientation: 'Right-top (rotated 90° clockwise)',
    gpsLatitude: 37.8,
    gpsLongitude: -122.25,
    gpsAltitudeMeters: -12.3,
  });
});

test('reads a standalone TIFF payload and returns no EXIF for unsupported or malformed data', () => {
  expect(extractExifMetadata(createTiff())).toMatchObject({ cameraMake: 'Canon', cameraModel: 'EOS R5' });
  expect(extractExifMetadata(new Uint8Array([0x89, 0x50, 0x4e, 0x47]))).toBeNull();
  expect(extractExifMetadata(wrapAsJpeg(createTiff()).subarray(0, 20))).toBeNull();
  expect(extractExifMetadata('not image bytes')).toBeNull();
});
