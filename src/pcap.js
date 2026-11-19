const MAX_CAPTURE_BYTES = 256 * 1024 * 1024;
const MAX_PACKETS = 500_000;
const MAX_CONNECTIONS = 20_000;
const MAX_SWEEP_PORTS = 10;

const TCP_FLAGS = {
  FIN: 0x01,
  SYN: 0x02,
  RST: 0x04,
  PSH: 0x08,
  ACK: 0x10,
  URG: 0x20,
  ECE: 0x40,
  CWR: 0x80,
};

function asBytes(input) {
  if (input instanceof Uint8Array) return input;
  if (ArrayBuffer.isView(input)) return new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
  if (input instanceof ArrayBuffer || Object.prototype.toString.call(input) === '[object ArrayBuffer]') return new Uint8Array(input);
  throw new TypeError('PCAP input must be an ArrayBuffer or byte array.');
}

function readView(bytes) {
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
}

function bounds(bytes, offset, length, message = 'The capture contains a truncated structure.') {
  if (!Number.isSafeInteger(offset) || !Number.isSafeInteger(length)
    || offset < 0 || length < 0 || offset + length > bytes.length) {
    throw new Error(message);
  }
}

function readU16(bytes, offset, littleEndian = true) {
  bounds(bytes, offset, 2);
  return readView(bytes).getUint16(offset, littleEndian);
}

function readU32(bytes, offset, littleEndian = true) {
  bounds(bytes, offset, 4);
  return readView(bytes).getUint32(offset, littleEndian);
}

function readI64(bytes, offset, littleEndian = true) {
  bounds(bytes, offset, 8);
  return Number(readView(bytes).getBigInt64(offset, littleEndian));
}

function formatTime(seconds) {
  if (!Number.isFinite(seconds)) return null;
  const date = new Date(seconds * 1000);
  return Number.isNaN(date.getTime()) ? null : date.toISOString();
}

function ipv4(bytes, offset) {
  return `${bytes[offset]}.${bytes[offset + 1]}.${bytes[offset + 2]}.${bytes[offset + 3]}`;
}

function ipv6(bytes, offset) {
  const groups = Array.from({ length: 8 }, (_, index) => (
    readU16(bytes, offset + index * 2, false).toString(16)
  ));
  let bestStart = -1;
  let bestLength = 1;
  for (let index = 0; index < groups.length;) {
    if (groups[index] !== '0') {
      index += 1;
      continue;
    }
    let end = index;
    while (end < groups.length && groups[end] === '0') end += 1;
    if (end - index > bestLength) {
      bestStart = index;
      bestLength = end - index;
    }
    index = end;
  }
  if (bestStart < 0) return groups.join(':');
  const left = groups.slice(0, bestStart).join(':');
  const right = groups.slice(bestStart + bestLength).join(':');
  return `${left}::${right}`;
}

function transportInfo(bytes, offset, end, protocol) {
  if (protocol === 6 && offset + 20 <= end) {
    const headerLength = (bytes[offset + 12] >> 4) * 4;
    if (headerLength < 20 || offset + headerLength > end) return { protocol: 'TCP' };
    const flags = bytes[offset + 13];
    return {
      protocol: 'TCP',
      sourcePort: readU16(bytes, offset, false),
      destinationPort: readU16(bytes, offset + 2, false),
      tcpFlags: flags,
      synOnly: (flags & TCP_FLAGS.SYN) !== 0 && (flags & TCP_FLAGS.ACK) === 0,
    };
  }
  if (protocol === 17 && offset + 8 <= end) {
    return {
      protocol: 'UDP',
      sourcePort: readU16(bytes, offset, false),
      destinationPort: readU16(bytes, offset + 2, false),
    };
  }
  if (protocol === 1) return { protocol: 'ICMP' };
  if (protocol === 58) return { protocol: 'ICMPv6' };
  return { protocol: `IP protocol ${protocol}` };
}

function parseIpPacket(bytes, offset, end) {
  bounds(bytes, offset, 1);
  const version = bytes[offset] >> 4;
  if (version === 4) {
    bounds(bytes, offset, 20);
    const headerLength = (bytes[offset] & 0x0f) * 4;
    if (headerLength < 20 || offset + headerLength > end) return null;
    const totalLength = readU16(bytes, offset + 2, false);
    if (totalLength < headerLength) return null;
    const packetEnd = Math.min(end, offset + totalLength);
    const fragment = readU16(bytes, offset + 6, false);
    const fragmentOffset = fragment & 0x1fff;
    const protocol = bytes[offset + 9];
    const source = ipv4(bytes, offset + 12);
    const destination = ipv4(bytes, offset + 16);
    const transport = fragmentOffset === 0
      ? transportInfo(bytes, offset + headerLength, packetEnd, protocol)
      : { protocol: protocol === 6 ? 'TCP' : protocol === 17 ? 'UDP' : `IP protocol ${protocol}` };
    return { source, destination, packetBytes: totalLength, ...transport };
  }
  if (version === 6) {
    bounds(bytes, offset, 40);
    const payloadLength = readU16(bytes, offset + 4, false);
    let protocol = bytes[offset + 6];
    let cursor = offset + 40;
    const packetEnd = Math.min(end, cursor + payloadLength);
    const source = ipv6(bytes, offset + 8);
    const destination = ipv6(bytes, offset + 24);
    for (let depth = 0; depth < 8 && [0, 43, 44, 51, 60].includes(protocol); depth += 1) {
      if (cursor + 2 > packetEnd) return null;
      bounds(bytes, cursor, 2);
      const nextProtocol = bytes[cursor];
      let extensionLength;
      if (protocol === 44) {
        if (cursor + 8 > packetEnd) return null;
        bounds(bytes, cursor, 8);
        const fragmentOffset = readU16(bytes, cursor + 2, false) >> 3;
        protocol = nextProtocol;
        cursor += 8;
        if (fragmentOffset !== 0) {
          return {
            source,
            destination,
            packetBytes: 40 + payloadLength,
            protocol: protocol === 6 ? 'TCP' : protocol === 17 ? 'UDP' : `IP protocol ${protocol}`,
          };
        }
        continue;
      }
      extensionLength = protocol === 51 ? (bytes[cursor + 1] + 2) * 4 : (bytes[cursor + 1] + 1) * 8;
      if (cursor + extensionLength > packetEnd) return null;
      bounds(bytes, cursor, extensionLength);
      cursor += extensionLength;
      protocol = nextProtocol;
    }
    return {
      source,
      destination,
      packetBytes: 40 + payloadLength,
      ...transportInfo(bytes, cursor, packetEnd, protocol),
    };
  }
  return null;
}

function parseLinkPacket(bytes, linkType) {
  if (!bytes.length) return null;
  let offset;
  let etherType;
  if (linkType === 1) {
    bounds(bytes, 0, 14);
    etherType = readU16(bytes, 12, false);
    offset = 14;
    for (let depth = 0; depth < 2 && [0x8100, 0x88a8, 0x9100].includes(etherType); depth += 1) {
      bounds(bytes, offset, 4);
      etherType = readU16(bytes, offset + 2, false);
      offset += 4;
    }
  } else if (linkType === 101 || linkType === 12) {
    offset = 0;
  } else if (linkType === 113) {
    bounds(bytes, 0, 16);
    etherType = readU16(bytes, 14, false);
    offset = 16;
  } else if (linkType === 276) {
    bounds(bytes, 0, 20);
    etherType = readU16(bytes, 0, false);
    offset = 20;
  } else if (linkType === 0 || linkType === 108) {
    bounds(bytes, 0, 4);
    const familyLittle = readU32(bytes, 0, true);
    const familyBig = readU32(bytes, 0, false);
    offset = 4;
    etherType = [2, 24, 28, 30].includes(familyLittle) ? 0x0800
      : [2, 24, 28, 30].includes(familyBig) ? 0x0800
        : [10, 23, 24, 28, 30].includes(familyLittle) ? 0x86dd
          : [10, 23, 24, 28, 30].includes(familyBig) ? 0x86dd : 0;
  } else {
    return null;
  }
  if (etherType !== undefined && etherType !== 0x0800 && etherType !== 0x86dd) return null;
  if (etherType === 0x0800 && bytes[offset] >> 4 !== 4) return null;
  if (etherType === 0x86dd && bytes[offset] >> 4 !== 6) return null;
  return parseIpPacket(bytes, offset, bytes.length);
}

function recordPacket(report, packet, timestamp, originalTimestamp = timestamp) {
  if (!packet) {
    report.nonIpPackets += 1;
    return;
  }
  report.packetCount += 1;
  if (report.packets.length < 1_000) {
    report.packets.push({
      timestamp,
      originalTimestamp,
      sourceIp: packet.source,
      destinationIp: packet.destination,
      sourcePort: packet.sourcePort ?? null,
      destinationPort: packet.destinationPort ?? null,
      protocol: packet.protocol,
      bytes: packet.packetBytes,
    });
  }
  const protocol = packet.protocol;
  const sourceEndpoint = `${packet.source}:${packet.sourcePort ?? '-'}`;
  const destinationEndpoint = `${packet.destination}:${packet.destinationPort ?? '-'}`;
  const [first, second] = [sourceEndpoint, destinationEndpoint].sort();
  const key = `${protocol}|${first}|${second}`;
  let connection = report.connectionMap.get(key);
  if (!connection) {
    if (report.connectionMap.size >= MAX_CONNECTIONS) {
      report.warnings.add(`Connection summaries were capped at ${MAX_CONNECTIONS.toLocaleString()} flows.`);
      return;
    }
    connection = {
      protocol,
      endpointA: first,
      endpointB: second,
      packets: 0,
      bytes: 0,
      firstSeen: timestamp,
      lastSeen: timestamp,
      originalFirstSeen: originalTimestamp,
      originalLastSeen: originalTimestamp,
      synOnlyPackets: 0,
      synSourceIp: null,
      synDestinationIp: null,
      synOnlyPorts: new Set(),
    };
    report.connectionMap.set(key, connection);
  }
  connection.packets += 1;
  connection.bytes += packet.packetBytes;
  connection.synOnlyPackets += packet.synOnly ? 1 : 0;
  if (packet.synOnly) {
    connection.synSourceIp = packet.source;
    connection.synDestinationIp = packet.destination;
    if (packet.destinationPort !== undefined) connection.synOnlyPorts.add(packet.destinationPort);
  }
  if (timestamp && (!connection.firstSeen || timestamp < connection.firstSeen)) {
    connection.firstSeen = timestamp;
    connection.originalFirstSeen = originalTimestamp;
  }
  if (timestamp && (!connection.lastSeen || timestamp > connection.lastSeen)) {
    connection.lastSeen = timestamp;
    connection.originalLastSeen = originalTimestamp;
  }
}

function addSweepLeads(report) {
  const sweepTargets = new Map();
  for (const connection of report.connectionMap.values()) {
    if (connection.protocol !== 'TCP' || !connection.synOnlyPackets) continue;
    const targetKey = `${connection.synSourceIp}|${connection.synDestinationIp}`;
    if (!sweepTargets.has(targetKey)) {
      sweepTargets.set(targetKey, {
        sourceIp: connection.synSourceIp,
        destinationIp: connection.synDestinationIp,
        ports: new Set(),
      });
    }
    connection.synOnlyPorts.forEach((port) => sweepTargets.get(targetKey).ports.add(port));
  }
  for (const target of sweepTargets.values()) {
    if (target.ports.size >= MAX_SWEEP_PORTS) {
      report.leads.push({
        indicator: 'Possible TCP port sweep pattern',
        classification: 'LEAD - NOT A CONFIRMED THREAT',
        sourceIp: target.sourceIp,
        destinationIp: target.destinationIp,
        distinctDestinationPorts: target.ports.size,
        note: `At least ${MAX_SWEEP_PORTS} destination ports received TCP SYN packets; benign scanning or monitoring can produce similar traffic.`,
      });
    }
  }
}

function createReport(format) {
  return {
    format,
    parsedAt: new Date().toISOString(),
    packetCount: 0,
    nonIpPackets: 0,
    packets: [],
    connectionMap: new Map(),
    leads: [],
    warnings: new Set(),
  };
}

function finishReport(report) {
  const normalizedConnections = [...report.connectionMap.values()].map(({
    synOnlyPackets,
    synSourceIp,
    synDestinationIp,
    synOnlyPorts,
    ...connection
  }) => ({
    ...connection,
    firstSeen: connection.firstSeen || null,
    lastSeen: connection.lastSeen || null,
  }));
  addSweepLeads(report);
  return {
    format: report.format,
    parsedAt: report.parsedAt,
    packetCount: report.packetCount,
    nonIpPackets: report.nonIpPackets,
    packets: report.packets,
    packetDetailsTruncated: report.packetCount > report.packets.length,
    connectionCount: report.connectionMap.size,
    connections: normalizedConnections,
    leads: report.leads,
    warnings: [...report.warnings],
  };
}

function parseClassicPcap(bytes) {
  if (bytes.length < 24) throw new Error('The PCAP global header is truncated.');
  const magic = Array.from(bytes.subarray(0, 4), (byte) => byte.toString(16).padStart(2, '0')).join('');
  const formats = {
    'd4c3b2a1': { littleEndian: true, resolution: 1e-6 },
    'a1b2c3d4': { littleEndian: false, resolution: 1e-6 },
    '4d3cb2a1': { littleEndian: true, resolution: 1e-9 },
    'a1b23c4d': { littleEndian: false, resolution: 1e-9 },
  };
  const format = formats[magic];
  if (!format) throw new Error('Unsupported capture format. Use a classic PCAP or PCAPNG file.');
  const { littleEndian, resolution } = format;
  const major = readU16(bytes, 4, littleEndian);
  const minor = readU16(bytes, 6, littleEndian);
  if (major !== 2 || minor < 4) throw new Error(`Unsupported PCAP version ${major}.${minor}.`);
  const snapLength = readU32(bytes, 16, littleEndian);
  const linkType = readU32(bytes, 20, littleEndian) & 0xffff;
  if (snapLength === 0) throw new Error('The PCAP snapshot length is invalid.');
  const report = createReport('PCAP');
  let offset = 24;
  let recordCount = 0;
  while (offset < bytes.length) {
    if (++recordCount > MAX_PACKETS) {
      report.warnings.add(`Packet parsing stopped at the ${MAX_PACKETS.toLocaleString()}-packet safety limit.`);
      break;
    }
    bounds(bytes, offset, 16, 'The PCAP packet record header is truncated.');
    const seconds = readU32(bytes, offset, littleEndian);
    const fraction = readU32(bytes, offset + 4, littleEndian);
    const capturedLength = readU32(bytes, offset + 8, littleEndian);
    const originalLength = readU32(bytes, offset + 12, littleEndian);
    if (capturedLength > snapLength || capturedLength > MAX_CAPTURE_BYTES) {
      throw new Error('A PCAP packet length exceeds the declared snapshot limit.');
    }
    bounds(bytes, offset + 16, capturedLength, 'A PCAP packet payload is truncated.');
    if (originalLength < capturedLength) report.warnings.add('At least one packet capture length exceeded its original packet length.');
    const rawTimestamp = { seconds, fraction, resolution };
    const timestamp = formatTime(seconds + fraction * resolution);
    try {
      recordPacket(report, parseLinkPacket(bytes.subarray(offset + 16, offset + 16 + capturedLength), linkType), timestamp, rawTimestamp);
    } catch {
      report.warnings.add('At least one packet was malformed or truncated and could not be fully decoded.');
    }
    offset += 16 + capturedLength;
  }
  if (![1, 12, 101, 108, 113, 276].includes(linkType)) {
    report.warnings.add(`Link type ${linkType} is not supported; packet details may be unavailable.`);
  }
  return finishReport(report);
}

function ngOptions(bytes, offset, end, littleEndian, callback) {
  let cursor = offset;
  while (cursor + 4 <= end) {
    const code = readU16(bytes, cursor, littleEndian);
    const length = readU16(bytes, cursor + 2, littleEndian);
    cursor += 4;
    if (code === 0) return;
    bounds(bytes, cursor, length);
    const paddedLength = (length + 3) & ~3;
    if (cursor + paddedLength > end) throw new Error('A PCAPNG option exceeds its block.');
    callback(code, cursor, length);
    cursor += paddedLength;
  }
}

function parsePcapNg(bytes) {
  const report = createReport('PCAPNG');
  const interfaces = [];
  let offset = 0;
  let littleEndian = true;
  let packetRecords = 0;
  while (offset < bytes.length) {
    bounds(bytes, offset, 12, 'A PCAPNG block header is truncated.');
    const isSectionHeader = readU32(bytes, offset, false) === 0x0a0d0d0a;
    if (isSectionHeader) {
      const bom = Array.from(bytes.subarray(offset + 8, offset + 12), (byte) => byte.toString(16).padStart(2, '0')).join('');
      if (bom === '4d3c2b1a') littleEndian = true;
      else if (bom === '1a2b3c4d') littleEndian = false;
      else throw new Error('The PCAPNG section byte-order marker is invalid.');
    }
    const blockType = readU32(bytes, offset, littleEndian);
    const blockLength = readU32(bytes, offset + 4, littleEndian);
    if (blockLength < 12 || blockLength % 4 !== 0) throw new Error('A PCAPNG block length is invalid.');
    bounds(bytes, offset, blockLength, 'A PCAPNG block is truncated.');
    if (readU32(bytes, offset + blockLength - 4, littleEndian) !== blockLength) {
      throw new Error('A PCAPNG block length trailer does not match.');
    }
    const body = offset + 8;
    const end = offset + blockLength - 4;
    if (isSectionHeader) {
      interfaces.length = 0;
      if (blockLength < 28) throw new Error('The PCAPNG section header is truncated.');
    } else if (blockType === 1) {
      if (body + 8 > end) throw new Error('A PCAPNG interface block is truncated.');
      const iface = { linkType: readU16(bytes, body, littleEndian), resolution: 1e-6, offsetSeconds: 0 };
      ngOptions(bytes, body + 8, end, littleEndian, (code, optionOffset, length) => {
        if (code === 9 && length >= 1) {
          const value = bytes[optionOffset];
          iface.resolution = value & 0x80 ? 2 ** -(value & 0x7f) : 10 ** -value;
        }
        if (code === 14 && length >= 8) iface.offsetSeconds = readI64(bytes, optionOffset, littleEndian);
      });
      interfaces.push(iface);
    } else if (blockType === 6 || blockType === 2) {
      if (++packetRecords > MAX_PACKETS) {
        report.warnings.add(`Packet parsing stopped at the ${MAX_PACKETS.toLocaleString()}-packet safety limit.`);
        break;
      }
      if (body + 20 > end) throw new Error('A PCAPNG enhanced packet block is truncated.');
      const interfaceId = blockType === 6
        ? readU32(bytes, body, littleEndian)
        : readU16(bytes, body, littleEndian);
      const iface = interfaces[interfaceId];
      if (!iface) throw new Error('A PCAPNG packet references an unknown interface.');
      const timestampOffset = body + 4;
      const ticks = readU32(bytes, timestampOffset, littleEndian) * 0x100000000 + readU32(bytes, timestampOffset + 4, littleEndian);
      const capturedLength = readU32(bytes, body + 12, littleEndian);
      const originalLength = readU32(bytes, body + 16, littleEndian);
      const packetOffset = body + 20;
      if (capturedLength > MAX_CAPTURE_BYTES || packetOffset + ((capturedLength + 3) & ~3) > end) {
        throw new Error('A PCAPNG packet payload exceeds its block.');
      }
      if (originalLength < capturedLength) report.warnings.add('At least one packet capture length exceeded its original packet length.');
      const rawTimestamp = { ticks, resolution: iface.resolution, offsetSeconds: iface.offsetSeconds };
      const timestamp = formatTime(ticks * iface.resolution + iface.offsetSeconds);
      try {
        recordPacket(report, parseLinkPacket(bytes.subarray(packetOffset, packetOffset + capturedLength), iface.linkType), timestamp, rawTimestamp);
      } catch {
        report.warnings.add('At least one packet was malformed or truncated and could not be fully decoded.');
      }
    } else if (blockType === 3) {
      if (++packetRecords > MAX_PACKETS) {
        report.warnings.add(`Packet parsing stopped at the ${MAX_PACKETS.toLocaleString()}-packet safety limit.`);
        break;
      }
      if (!interfaces[0] || body + 4 > end) throw new Error('A PCAPNG simple packet block has no interface or packet length.');
      const originalLength = readU32(bytes, body, littleEndian);
      const capturedLength = Math.min(originalLength, end - body - 4);
      try {
        recordPacket(report, parseLinkPacket(bytes.subarray(body + 4, body + 4 + capturedLength), interfaces[0].linkType), null);
      } catch {
        report.warnings.add('At least one packet was malformed or truncated and could not be fully decoded.');
      }
    }
    offset += blockLength;
  }
  return finishReport(report);
}

export function parsePcap(input) {
  const bytes = asBytes(input);
  if (bytes.length > MAX_CAPTURE_BYTES) throw new Error('The capture exceeds the 256 MiB local analysis limit.');
  if (bytes.length < 4) throw new Error('The capture file is too small to identify.');
  if (readU32(bytes, 0, false) === 0x0a0d0d0a) return parsePcapNg(bytes);
  return parseClassicPcap(bytes);
}
