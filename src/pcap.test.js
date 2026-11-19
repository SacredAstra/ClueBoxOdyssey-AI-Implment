import { expect, test } from 'vitest';
import { parsePcap } from './pcap';

function makeEthernetPacket({ protocol = 6, sourceIp = [192, 0, 2, 10], destinationIp = [198, 51, 100, 20], sourcePort = 51514, destinationPort = 443, flags = 0x18 } = {}) {
  const transportLength = protocol === 6 ? 20 : 8;
  const packet = new Uint8Array(14 + 20 + transportLength);
  const view = new DataView(packet.buffer);
  packet.set([0x08, 0x00], 12);
  packet[14] = 0x45;
  view.setUint16(16, 20 + transportLength, false);
  packet[22] = 64;
  packet[23] = protocol;
  packet.set(sourceIp, 26);
  packet.set(destinationIp, 30);
  view.setUint16(34, sourcePort, false);
  view.setUint16(36, destinationPort, false);
  if (protocol === 6) {
    packet[46] = 0x50;
    packet[47] = flags;
  } else {
    view.setUint16(38, transportLength, false);
  }
  return packet;
}

function makeClassicPcap(records, { littleEndian = true, nanosecond = false } = {}) {
  const header = new Uint8Array(24);
  const view = new DataView(header.buffer);
  header.set(nanosecond
    ? (littleEndian ? [0x4d, 0x3c, 0xb2, 0xa1] : [0xa1, 0xb2, 0x3c, 0x4d])
    : (littleEndian ? [0xd4, 0xc3, 0xb2, 0xa1] : [0xa1, 0xb2, 0xc3, 0xd4]));
  view.setUint16(4, 2, littleEndian);
  view.setUint16(6, 4, littleEndian);
  view.setUint32(16, 65535, littleEndian);
  view.setUint32(20, 1, littleEndian);
  const length = records.reduce((total, { packet }) => total + 16 + packet.length, header.length);
  const bytes = new Uint8Array(length);
  bytes.set(header);
  const resultView = new DataView(bytes.buffer);
  let offset = header.length;
  records.forEach(({ packet, seconds = 1_700_000_000, fraction = 500_000 }) => {
    resultView.setUint32(offset, seconds, littleEndian);
    resultView.setUint32(offset + 4, fraction, littleEndian);
    resultView.setUint32(offset + 8, packet.length, littleEndian);
    resultView.setUint32(offset + 12, packet.length, littleEndian);
    bytes.set(packet, offset + 16);
    offset += 16 + packet.length;
  });
  return bytes;
}

function makePcapNg(packet) {
  const padLength = (4 - (packet.length % 4)) % 4;
  const enhancedBlockLength = 32 + packet.length + padLength;
  const bytes = new Uint8Array(28 + 20 + enhancedBlockLength);
  const view = new DataView(bytes.buffer);
  const put32 = (offset, value) => view.setUint32(offset, value, true);

  put32(0, 0x0a0d0d0a);
  put32(4, 28);
  put32(8, 0x1a2b3c4d);
  view.setUint16(12, 1, true);
  view.setUint16(14, 0, true);
  view.setBigInt64(16, -1n, true);
  put32(24, 28);

  put32(28, 1);
  put32(32, 20);
  view.setUint16(36, 1, true);
  view.setUint16(38, 0, true);
  put32(40, 65535);
  put32(44, 20);

  put32(48, 6);
  put32(52, enhancedBlockLength);
  put32(56, 0);
  const timestampTicks = 1_700_000_000_000_000n;
  put32(60, Number(timestampTicks >> 32n));
  put32(64, Number(timestampTicks & 0xffffffffn));
  put32(68, packet.length);
  put32(72, packet.length);
  bytes.set(packet, 76);
  put32(48 + enhancedBlockLength - 4, enhancedBlockLength);
  return bytes;
}

test('parses classic PCAP timestamps, endpoints, protocols, and bidirectional connection summaries', () => {
  const tcp = makeEthernetPacket();
  const udp = makeEthernetPacket({ protocol: 17, sourceIp: [192, 0, 2, 15], destinationIp: [203, 0, 113, 9], sourcePort: 53000, destinationPort: 53 });
  const response = makeEthernetPacket({ protocol: 17, sourceIp: [203, 0, 113, 9], destinationIp: [192, 0, 2, 15], sourcePort: 53, destinationPort: 53000 });
  const report = parsePcap(makeClassicPcap([{ packet: tcp }, { packet: udp }, { packet: response }]));

  expect(report.format).toBe('PCAP');
  expect(report.packetCount).toBe(3);
  expect(report.packets[0]).toMatchObject({
    timestamp: '2023-11-14T22:13:20.500Z',
    originalTimestamp: { seconds: 1_700_000_000, fraction: 500_000, resolution: 0.000001 },
    sourceIp: '192.0.2.10',
    destinationIp: '198.51.100.20',
    sourcePort: 51514,
    destinationPort: 443,
    protocol: 'TCP',
  });
  expect(report.connectionCount).toBe(2);
  expect(report.connections).toContainEqual(expect.objectContaining({
    protocol: 'UDP',
    packets: 2,
    endpointA: '192.0.2.15:53000',
    endpointB: '203.0.113.9:53',
    firstSeen: '2023-11-14T22:13:20.500Z',
  }));
  expect(report.leads).toEqual([]);
});

test('supports big-endian nanosecond captures and labels repeated SYN ports as leads', () => {
  const records = Array.from({ length: 10 }, (_, index) => ({
    packet: makeEthernetPacket({ sourcePort: 40000, destinationPort: 8000 + index, flags: 0x02 }),
    fraction: 125_000_000,
  }));
  const report = parsePcap(makeClassicPcap(records, { littleEndian: false, nanosecond: true }));

  expect(report.packets[0].timestamp).toBe('2023-11-14T22:13:20.125Z');
  expect(report.leads).toEqual([expect.objectContaining({
    indicator: 'Possible TCP port sweep pattern',
    classification: 'LEAD - NOT A CONFIRMED THREAT',
    sourceIp: '192.0.2.10',
    destinationIp: '198.51.100.20',
    distinctDestinationPorts: 10,
  })]);
});

test('parses PCAPNG enhanced packet blocks and rejects malformed captures', () => {
  const report = parsePcap(makePcapNg(makeEthernetPacket({ protocol: 17, sourcePort: 12345, destinationPort: 123 })));
  expect(report).toMatchObject({
    format: 'PCAPNG',
    packetCount: 1,
    packets: [{
      timestamp: '2023-11-14T22:13:20.000Z',
      protocol: 'UDP',
      sourcePort: 12345,
      destinationPort: 123,
    }],
  });
  expect(() => parsePcap(new Uint8Array(24))).toThrow(/Unsupported capture format/);
  expect(() => parsePcap(new Uint8Array([0xd4, 0xc3, 0xb2, 0xa1]))).toThrow(/global header is truncated/);
  expect(() => parsePcap('not a capture')).toThrow(/ArrayBuffer or byte array/);
});
