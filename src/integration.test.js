import { expect, test, vi } from 'vitest';
import initSqlJs from 'sql.js';
import { analyzeSqlite } from './sqlite';
import { parsePcap } from './pcap';
import {
  addCustodyEvent,
  downloadEvidence,
  getCaseRecords,
  getCases,
  saveEvidence,
  savePcapAnalysis,
  saveSqliteAnalysis,
  verifyCustody,
} from './vault';
import {
  createInvestigationReport,
  createTimelineEvents,
  timelineToCsv,
} from './timeline';
import { buildCopilotEvidenceContext, callCopilot, COPILOT_UNAVAILABLE_MESSAGE } from './copilot';

const { wasmPath } = vi.hoisted(() => ({
  wasmPath: `${process.cwd()}/node_modules/sql.js/dist/sql-wasm.wasm`,
}));

vi.mock('sql.js/dist/sql-wasm.wasm?url', () => ({
  default: wasmPath,
}));

const SQL = initSqlJs({ locateFile: () => wasmPath });
const CASE_ID = 'E2E-SYNTHETIC-CASE-ONLY';
const encoder = new TextEncoder();

function createMemoryVault() {
  const stores = { records: new Map(), keys: new Map(), cases: new Map() };
  return {
    stores,
    transaction() {
      const transaction = {};
      transaction.objectStore = (name) => {
        const store = stores[name];
        return {
          put(value) {
            return createRequest(() => {
              const key = value.id || value.caseId;
              store.set(key, value);
              return key;
            }, transaction);
          },
          get(key) {
            return createRequest(() => store.get(key));
          },
          getAll() {
            return createRequest(() => [...store.values()]);
          },
          index() {
            return {
              getAll(value) {
                return createRequest(() => [...store.values()].filter((item) => item.caseId === value));
              },
            };
          },
        };
      };
      return transaction;
    },
  };
}

function createRequest(operation, transaction) {
  const request = {};
  queueMicrotask(() => {
    try {
      request.result = operation();
      request.onsuccess?.({ target: request });
      if (transaction) queueMicrotask(() => transaction.oncomplete?.({ target: transaction }));
    } catch (error) {
      request.error = error;
      request.onerror?.({ target: request });
      transaction?.onerror?.({ target: transaction });
    }
  });
  return request;
}

function createFile(name, type, bytes) {
  const contents = encoder.encode('\0'.repeat(bytes.byteLength));
  contents.set(bytes);
  return {
    name,
    type,
    size: contents.byteLength,
    lastModified: Date.parse('2026-10-30T10:00:00.000Z'),
    arrayBuffer: async () => {
      return contents.slice().buffer;
    },
  };
}

function createEthernetPacket() {
  const packet = new Uint8Array(14 + 20 + 20);
  const view = new DataView(packet.buffer);
  packet.set([0x08, 0x00], 12);
  packet[14] = 0x45;
  view.setUint16(16, 40, false);
  packet[22] = 64;
  packet[23] = 6;
  packet.set([192, 0, 2, 44], 26);
  packet.set([198, 51, 100, 9], 30);
  view.setUint16(34, 52_000, false);
  view.setUint16(36, 443, false);
  packet[46] = 0x50;
  packet[47] = 0x18;
  return packet;
}

function createPcapEvidence() {
  const packet = createEthernetPacket();
  const bytes = new Uint8Array(24 + 16 + packet.length);
  const view = new DataView(bytes.buffer);
  bytes.set([0xd4, 0xc3, 0xb2, 0xa1]);
  view.setUint16(4, 2, true);
  view.setUint16(6, 4, true);
  view.setUint32(16, 65_535, true);
  view.setUint32(20, 1, true);
  view.setUint32(24, 1_793_368_800, true);
  view.setUint32(28, 250_000, true);
  view.setUint32(32, packet.length, true);
  view.setUint32(36, packet.length, true);
  bytes.set(packet, 40);
  return bytes;
}

async function createSqliteEvidence() {
  const SQLModule = await SQL;
  const database = new SQLModule.Database();
  database.run(`
    CREATE TABLE activity (
      id INTEGER PRIMARY KEY,
      created_at TEXT NOT NULL,
      detail TEXT
    );
    INSERT INTO activity (created_at, detail)
    VALUES ('2026-10-30 12:30:00', 'harmless synthetic activity');
  `);
  const bytes = database.export();
  database.close();
  return bytes;
}

function readBlobArrayBuffer(blob) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result);
    reader.onerror = () => reject(reader.error);
    reader.readAsArrayBuffer(blob);
  });
}

test('completes isolated synthetic case workflow from encrypted upload through timeline and report export', async () => {
  const database = createMemoryVault();
  const pcapBytes = createPcapEvidence();
  const sqliteBytes = await createSqliteEvidence();
  const originalPcap = pcapBytes.slice();
  const originalSqlite = sqliteBytes.slice();

  const pcapEvidenceId = await saveEvidence(database, {
    file: createFile('synthetic-capture.pcap', 'application/vnd.tcpdump.pcap', pcapBytes),
    caseId: CASE_ID,
    custodian: 'Synthetic Test Custodian',
  });
  const sqliteEvidenceId = await saveEvidence(database, {
    file: createFile('synthetic-activity.sqlite', 'application/vnd.sqlite3', sqliteBytes),
    caseId: CASE_ID,
    custodian: 'Synthetic Test Custodian',
  });

  expect(await getCases(database)).toContain(CASE_ID);
  let records = await getCaseRecords(database, CASE_ID);
  expect(records).toHaveLength(2);
  const pcapRecord = records.find((record) => record.id === pcapEvidenceId);
  const sqliteRecord = records.find((record) => record.id === sqliteEvidenceId);
  expect(pcapRecord.sha256).toMatch(/^[a-f0-9]{64}$/);
  expect(sqliteRecord.sha256).toMatch(/^[a-f0-9]{64}$/);
  expect(database.stores.records.get(pcapEvidenceId).file.ciphertext).not.toEqual(originalPcap);
  expect(database.stores.records.get(sqliteEvidenceId).file.ciphertext).not.toEqual(originalSqlite);

  const verifiedPcapCopy = await downloadEvidence(database, pcapEvidenceId);
  const verifiedSqliteCopy = await downloadEvidence(database, sqliteEvidenceId);
  const verifiedPcapBytes = await readBlobArrayBuffer(verifiedPcapCopy);
  const verifiedSqliteBytes = await readBlobArrayBuffer(verifiedSqliteCopy);
  expect(new Uint8Array(verifiedPcapBytes)).toEqual(originalPcap);
  expect(new Uint8Array(verifiedSqliteBytes)).toEqual(originalSqlite);

  const pcapReport = parsePcap(verifiedPcapBytes);
  const sqliteReport = await analyzeSqlite(verifiedSqliteBytes, 'synthetic-activity.sqlite');
  expect(pcapReport.packetCount).toBe(1);
  expect(pcapReport.packets[0]).toMatchObject({
    sourceIp: '192.0.2.44',
    destinationIp: '198.51.100.9',
    protocol: 'TCP',
  });
  expect(sqliteReport.tables.find((table) => table.name === 'activity').records[0].detail).toBe('harmless synthetic activity');

  await savePcapAnalysis(database, pcapEvidenceId, {
    report: pcapReport,
    status: 'VERIFIED',
    analyst: 'Synthetic Human Reviewer',
    notes: 'Compared the generated report with the independently parsed synthetic capture.',
    artifactReferences: ['PCAP-SYN-01 / packet 1', ''],
  });
  await saveSqliteAnalysis(database, sqliteEvidenceId, {
    report: sqliteReport,
    status: 'NEEDS REVIEW',
    analyst: 'Synthetic Database Reviewer',
    notes: 'Timestamp has no explicit timezone; retain as ambiguous.',
    artifactReferences: ['SQL-SYN-01 / activity.created_at'],
  });
  await addCustodyEvent(database, pcapEvidenceId, 'Synthetic Human Reviewer', 'Evidence reviewed');

  records = await getCaseRecords(database, CASE_ID);
  expect(records.find((record) => record.id === pcapEvidenceId).pcapAnalysis.artifactReferences).toEqual(['PCAP-SYN-01 / packet 1']);
  expect(await verifyCustody(records.find((record) => record.id === pcapEvidenceId).custody)).toBe(true);

  const events = createTimelineEvents(CASE_ID, records, {
    [pcapEvidenceId]: { custody: true },
    [sqliteEvidenceId]: { custody: true },
  });
  expect(events.some((event) => event.sourceModule === 'PCAP' && event.timestamp === '2026-10-30T14:00:00.250Z')).toBe(true);
  expect(events.some((event) => event.sourceModule === 'SQLite' && event.timestamp === null
    && event.timestampStatus === 'AMBIGUOUS — TIME ZONE UNKNOWN')).toBe(true);
  expect(events.some((event) => event.sourceModule === 'Chain of custody' && event.validationStatus === 'VERIFIED')).toBe(true);

  const beforeReport = records.map((record) => ({
    id: record.id,
    sha256: record.sha256,
    custody: structuredClone(record.custody),
    ciphertext: database.stores.records.get(record.id).file.ciphertext.slice(0),
    metadataCiphertext: database.stores.records.get(record.id).metadata.ciphertext.slice(0),
  }));
  const report = createInvestigationReport({
    caseId: CASE_ID,
    records,
    timelineEvents: events,
    integrity: {
      [pcapEvidenceId]: { sha256: 'SHA-256 verified', custody: 'VERIFIED' },
      [sqliteEvidenceId]: { sha256: 'SHA-256 verified', custody: 'VERIFIED' },
    },
    summary: 'Synthetic end-to-end investigation.',
    conclusions: 'The synthetic workflows completed; no real evidence was used.',
    generatedAt: '2026-10-31T00:00:00.000Z',
  });
  const jsonExport = JSON.stringify(report);
  const csvExport = timelineToCsv(events);

  expect(JSON.parse(jsonExport).format).toBe('ForensiAI Investigation Report');
  expect(report.evidenceInventory).toHaveLength(2);
  expect(report.classifications.verifiedFindings).toEqual([]);
  expect(report.aiAssistedInterpretations).toEqual([]);
  expect(report.humanValidationResults.some((validation) => validation.module === 'pcapAnalysis' && validation.status === 'VERIFIED')).toBe(true);
  expect(csvExport).toContain('PCAP');
  expect(csvExport).toContain('SQLite');
  expect(csvExport).toContain(CASE_ID);
  expect(report.limitations.some((item) => item.includes('time zone'))).toBe(true);

  for (const before of beforeReport) {
    const stored = database.stores.records.get(before.id);
    const [after] = await getCaseRecords(database, CASE_ID).then((items) => items.filter((item) => item.id === before.id));
    expect(after.sha256).toBe(before.sha256);
    expect(after.custody).toEqual(before.custody);
    expect(stored.file.ciphertext).toEqual(before.ciphertext);
    expect(stored.metadata.ciphertext).toEqual(before.metadataCiphertext);
  }
});

test('rejects unauthorized Copilot requests and surfaces missing AI configuration without network access', async () => {
  let fetchCalls = 0;
  await expect(callCopilot({ action: 'ask', fetchImpl: async () => { fetchCalls += 1; } }))
    .rejects.toThrow(COPILOT_UNAVAILABLE_MESSAGE);
  expect(fetchCalls).toBe(0);

  await expect(callCopilot({
    supabaseUrl: 'https://synthetic-project.supabase.co',
    publishableKey: 'synthetic-public-key',
    accessToken: 'synthetic-invalid-token',
    action: 'ask',
    payload: { caseNumber: CASE_ID },
    fetchImpl: async () => {
      fetchCalls += 1;
      return new Response(JSON.stringify({ error: 'Access denied.' }), { status: 403 });
    },
  })).rejects.toThrow(/access denied/i);
  expect(fetchCalls).toBe(1);

  await expect(buildCopilotEvidenceContext(CASE_ID, [{
    id: 'foreign-case-evidence',
    caseId: 'UNAUTHORIZED-CASE',
  }], async () => true, async () => true)).rejects.toThrow(/active case/i);
});

test('detects corrupted encrypted data and rejects unsupported evidence formats without modifying evidence', async () => {
  const database = createMemoryVault();
  const unsupportedBytes = new Uint8Array(32).fill(0x20);
  const unsupportedId = await saveEvidence(database, {
    file: createFile('unsupported-synthetic.bin', 'application/octet-stream', unsupportedBytes),
    caseId: CASE_ID,
    custodian: 'Synthetic Test Custodian',
  });
  const unsupportedCiphertext = database.stores.records.get(unsupportedId).file.ciphertext.slice(0);
  const [before] = await getCaseRecords(database, CASE_ID);
  const unsupportedCopy = await downloadEvidence(database, unsupportedId);
  const decryptedUnsupportedBytes = await readBlobArrayBuffer(unsupportedCopy);
  expect(() => parsePcap(decryptedUnsupportedBytes)).toThrow(/unsupported capture format/i);
  await expect(analyzeSqlite(decryptedUnsupportedBytes, 'unsupported-synthetic.bin')).rejects.toThrow(/not a supported SQLite/i);
  expect(database.stores.records.get(unsupportedId).file.ciphertext).toEqual(unsupportedCiphertext);
  expect((await getCaseRecords(database, CASE_ID))[0].sha256).toBe(before.sha256);

  const key = database.stores.keys.get('evidence-encryption-key').key;
  const alteredBytes = encoder.encode('modified harmless synthetic content');
  const iv = crypto.getRandomValues(new Uint8Array(12));
  database.stores.records.get(unsupportedId).file = {
    iv: Array.from(iv),
    ciphertext: await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, alteredBytes),
  };
  await expect(downloadEvidence(database, unsupportedId)).rejects.toThrow(/SHA-256 verification failed/i);
});
