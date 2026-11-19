import { expect, test } from 'vitest';
import {
  addCustodyEvent,
  archiveEvidenceRecord,
  downloadEvidence,
  getCaseDetails,
  getCaseRecords,
  getCases,
  saveCaseDetails,
  saveCopilotFinding,
  saveExifValidation,
  savePcapAnalysis,
  saveRegistryAnalysis,
  saveSqliteAnalysis,
  saveEvidence,
  replaceEvidence,
  validateCopilotFinding,
  verifyCustody,
  verifyEvidenceIntegrity,
} from './vault';

const sampleText = 'Harmless temporary evidence sample for vault tests.\n';
const expectedSha256 = 'e15a12a20e3c0e0a5b68e8556b1bbb17800ec963a68c384fe20bdb75db9d4c93';
const encoder = new TextEncoder();

function createMemoryVault() {
  const stores = { records: new Map(), keys: new Map(), cases: new Map() };
  const database = {
    stores,
    transaction(storeName) {
      const transaction = {
        pendingWrites: 0,
        abort() {
          queueMicrotask(() => transaction.onabort?.({ target: transaction }));
        },
      };
      transaction.objectStore = (name) => {
        const store = stores[name];
        return {
          put(value) {
            transaction.pendingWrites += 1;
            return createRequest(() => {
              const key = value.id || value.caseId;
              store.set(key, value);
              return key;
            }, transaction, true);
          },
          add(value) {
            transaction.pendingWrites += 1;
            return createRequest(() => {
              const key = value.id || value.caseId;
              if (store.has(key)) throw new Error('Evidence ID already exists.');
              store.set(key, value);
              return key;
            }, transaction, true);
          },
          get(key) {
            return createRequest(() => {
              const value = store.get(key);
              return value === undefined ? undefined : structuredClone(value);
            });
          },
          getAll() {
            return createRequest(() => [...store.values()].map((value) => structuredClone(value)));
          },
          index() {
            return {
              getAll(value) {
                return createRequest(() => [...store.values()]
                  .filter((item) => item.caseId === value)
                  .map((item) => structuredClone(item)));
              },
            };
          },
        };
      };
      return transaction;
    },
  };
  return database;
}

function createRequest(operation, transaction, isWrite = false) {
  const request = {};
  queueMicrotask(() => {
    try {
      request.result = operation();
      request.onsuccess?.({ target: request });
      if (transaction && isWrite) {
        transaction.pendingWrites -= 1;
        if (!transaction.pendingWrites) queueMicrotask(() => transaction.oncomplete?.({ target: transaction }));
      }
    } catch (error) {
      request.error = error;
      request.onerror?.({ target: request });
      transaction?.onerror?.({ target: transaction });
    }
  });
  return request;
}

function readBlobText(blob) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result);
    reader.onerror = () => reject(reader.error);
    reader.readAsText(blob);
  });
}

async function saveSample(database) {
  const fileBytes = encoder.encode(sampleText);
  const file = {
    name: 'temporary-sample.txt',
    type: 'text/plain',
    size: fileBytes.byteLength,
    lastModified: 1_700_000_000_000,
    arrayBuffer: async () => fileBytes.buffer,
  };
  return saveEvidence(database, {
    file,
    caseId: 'TEST-ONLY',
    custodian: 'Automated Test',
  });
}

function makeReplacementFile(name, text) {
  const bytes = encoder.encode(text);
  return {
    name,
    type: 'text/plain',
    size: bytes.byteLength,
    lastModified: 1_700_000_100_000,
    arrayBuffer: async () => bytes.slice().buffer,
  };
}

function makeSampleExifJpeg() {
  const tiff = new Uint8Array(31);
  const view = new DataView(tiff.buffer);
  tiff.set([0x49, 0x49]);
  view.setUint16(2, 42, true);
  view.setUint32(4, 8, true);
  view.setUint16(8, 1, true);
  view.setUint16(10, 0x010f, true);
  view.setUint16(12, 2, true);
  view.setUint32(14, 5, true);
  view.setUint32(18, 26, true);
  view.setUint32(22, 0, true);
  tiff.set(new TextEncoder().encode('Test\0'), 26);

  const segmentLength = tiff.length + 8;
  const jpeg = new Uint8Array(tiff.length + 14);
  jpeg.set([0xff, 0xd8, 0xff, 0xe1, segmentLength >> 8, segmentLength & 0xff, 0x45, 0x78, 0x69, 0x66, 0, 0]);
  jpeg.set(tiff, 12);
  jpeg.set([0xff, 0xd9], 12 + tiff.length);
  const compatibleBytes = encoder.encode('\0'.repeat(jpeg.length));
  compatibleBytes.set(jpeg);
  return compatibleBytes;
}

test('hashes sample evidence with SHA-256 and decrypts it for download', async () => {
  const database = createMemoryVault();
  const id = await saveSample(database);
  const [record] = await getCaseRecords(database, 'TEST-ONLY');

  expect(record.sha256).toBe(expectedSha256);

  const encryptedFile = database.stores.records.get(id).file;
  expect(new Uint8Array(encryptedFile.ciphertext)).not.toEqual(encoder.encode(sampleText));
  await expect(readBlobText(await downloadEvidence(database, id))).resolves.toBe(sampleText);
});

test('archives evidence without removing original bytes, hash, reports, or custody history', async () => {
  const database = createMemoryVault();
  const id = await saveSample(database);
  const report = {
    format: 'Windows Registry Hive (REGF)',
    hiveType: 'SOFTWARE',
    parsedAt: '2026-10-30T00:00:00.000Z',
    keyCount: 1,
    artifacts: [{ type: 'Startup command', keyPath: 'Software\\Run', values: [] }],
    warnings: [],
  };
  await saveRegistryAnalysis(database, id, {
    report,
    status: 'VERIFIED',
    analyst: 'Registry Analyst',
    notes: 'Existing report to retain.',
    artifactReferences: ['REF-100'],
  });
  const [before] = await getCaseRecords(database, 'TEST-ONLY');
  const originalCiphertext = database.stores.records.get(id).file.ciphertext.slice(0);

  const archived = await archiveEvidenceRecord(database, id, {
    analyst: '  Case Investigator  ',
    reason: '  Superseded intake record; retained for historical review.  ',
    userId: 'investigator-1',
  });
  const [after] = await getCaseRecords(database, 'TEST-ONLY');

  expect(archived.id).toBe(id);
  expect(Date.parse(archived.archivedAt)).not.toBeNaN();
  expect(after).toMatchObject({
    id,
    sha256: before.sha256,
    archivedAt: archived.archivedAt,
    archive: {
      action: 'removed',
      analyst: 'Case Investigator',
      userId: 'investigator-1',
      reason: 'Superseded intake record; retained for historical review.',
      originalEvidenceId: id,
      replacementEvidenceId: null,
    },
    registryAnalysis: before.registryAnalysis,
  });
  expect(database.stores.records.get(id).file.ciphertext).toEqual(originalCiphertext);
  expect(after.custody.slice(0, before.custody.length)).toEqual(before.custody);
  expect(after.custody.at(-1)).toMatchObject({
    actor: 'Case Investigator',
    action: 'Evidence removed from case',
    details: {
      action: 'remove_from_case',
      analyst: 'Case Investigator',
      userId: 'investigator-1',
      reason: 'Superseded intake record; retained for historical review.',
      originalEvidenceId: id,
      replacementEvidenceId: null,
    },
  });
  expect(await verifyCustody(after.custody)).toBe(true);
  await expect(readBlobText(await downloadEvidence(database, id))).resolves.toBe(sampleText);
  await expect(archiveEvidenceRecord(database, id, { analyst: 'Analyst', reason: 'Repeat' }))
    .rejects.toThrow(/already archived/i);
});

test('replacement creates a linked new record and preserves all original forensic history', async () => {
  const database = createMemoryVault();
  const originalId = await saveSample(database);
  const report = {
    format: 'Windows Registry Hive (REGF)',
    hiveType: 'SOFTWARE',
    parsedAt: '2026-10-30T00:00:00.000Z',
    keyCount: 1,
    artifacts: [{ type: 'Startup command', keyPath: 'Software\\Run', values: [] }],
    warnings: [],
  };
  await saveRegistryAnalysis(database, originalId, {
    report,
    status: 'NEEDS REVIEW',
    analyst: 'Registry Analyst',
    notes: 'Preserve this historical report.',
    artifactReferences: ['REG-REF-2'],
  });
  const [before] = await getCaseRecords(database, 'TEST-ONLY');
  const originalCiphertext = database.stores.records.get(originalId).file.ciphertext.slice(0);
  const file = makeReplacementFile('replacement-sample.txt', 'Harmless replacement sample.\n');

  const replacementId = await replaceEvidence(database, originalId, {
    file,
    analyst: 'Replacement Investigator',
    reason: 'Corrected acquisition from source device.',
    userId: 'investigator-1',
  });
  const records = await getCaseRecords(database, 'TEST-ONLY');
  const original = records.find((record) => record.id === originalId);
  const replacement = records.find((record) => record.id === replacementId);

  expect(replacementId).not.toBe(originalId);
  expect(records).toHaveLength(2);
  expect(original.sha256).toBe(before.sha256);
  expect(original.registryAnalysis).toEqual(before.registryAnalysis);
  expect(original.replacementEvidenceId).toBe(replacementId);
  expect(original.archive).toMatchObject({
    action: 'replaced',
    analyst: 'Replacement Investigator',
    userId: 'investigator-1',
    reason: 'Corrected acquisition from source device.',
    originalEvidenceId: originalId,
    replacementEvidenceId: replacementId,
  });
  expect(original.custody.at(-1)).toMatchObject({
    action: 'Evidence replaced',
    details: {
      action: 'replace_evidence',
      analyst: 'Replacement Investigator',
      userId: 'investigator-1',
      reason: 'Corrected acquisition from source device.',
      originalEvidenceId: originalId,
      replacementEvidenceId: replacementId,
    },
  });
  expect(replacement).toMatchObject({
    id: replacementId,
    caseId: 'TEST-ONLY',
    name: 'replacement-sample.txt',
    replacement: {
      originalEvidenceId: originalId,
      analyst: 'Replacement Investigator',
      userId: 'investigator-1',
      reason: 'Corrected acquisition from source device.',
    },
    custody: [{
      action: 'Evidence received as replacement',
      details: {
        originalEvidenceId: originalId,
        replacementEvidenceId: replacementId,
      },
    }],
  });
  expect(replacement.sha256).not.toBe(before.sha256);
  expect(replacement.custody[0].timestamp).toBe(original.custody.at(-1).timestamp);
  expect(database.stores.records.get(originalId).file.ciphertext).toEqual(originalCiphertext);
  expect(original.custody.slice(0, before.custody.length)).toEqual(before.custody);
  expect(await verifyCustody(original.custody)).toBe(true);
  expect(await verifyCustody(replacement.custody)).toBe(true);
  await expect(readBlobText(await downloadEvidence(database, originalId))).resolves.toBe(sampleText);
  await expect(readBlobText(await downloadEvidence(database, replacementId))).resolves.toBe('Harmless replacement sample.\n');
  await expect(verifyEvidenceIntegrity(database, replacementId, replacement.sha256))
    .resolves.toMatchObject({ status: 'MATCH' });
});

test('stores encrypted case details, preserves the case ID and creation date, and reopens saved values', async () => {
  const database = createMemoryVault();
  const caseId = 'PRESERVE-CASE-001';
  const initial = await getCaseDetails(database, caseId);
  const saved = await saveCaseDetails(database, {
    ...initial,
    caseId,
    title: 'Incident response review',
    leadInvestigator: 'Investigator One',
    description: 'Review access activity and associated artifacts.',
    status: 'In Progress',
  });

  expect(saved).toMatchObject({
    caseId,
    title: 'Incident response review',
    leadInvestigator: 'Investigator One',
    description: 'Review access activity and associated artifacts.',
    status: 'In Progress',
    createdAt: initial.createdAt,
  });
  expect(Date.parse(saved.updatedAt)).toBeGreaterThanOrEqual(Date.parse(saved.createdAt));
  expect(database.stores.cases.get(caseId)).not.toHaveProperty('title');
  expect(JSON.stringify(database.stores.cases.get(caseId))).not.toContain('Incident response review');
  await expect(getCaseDetails(database, caseId)).resolves.toEqual(saved);
  await expect(getCases(database)).resolves.toContain(caseId);

  const updated = await saveCaseDetails(database, { ...saved, status: 'Under Review' });
  expect(updated.createdAt).toBe(saved.createdAt);
  expect(Date.parse(updated.updatedAt)).toBeGreaterThanOrEqual(Date.parse(saved.updatedAt));
  await expect(getCaseDetails(database, caseId)).resolves.toEqual(updated);
});

test('case details reject invalid status without changing stored case details', async () => {
  const database = createMemoryVault();
  const caseId = 'PRESERVE-CASE-002';
  const initial = await getCaseDetails(database, caseId);
  const saved = await saveCaseDetails(database, { ...initial, caseId, title: 'Unchanged' });
  await expect(saveCaseDetails(database, { ...saved, status: 'Archived' })).rejects.toThrow('Choose a valid case status.');
  await expect(getCaseDetails(database, caseId)).resolves.toEqual(saved);
});

test('adding case details to a legacy case leaves its evidence record and original case ID untouched', async () => {
  const database = createMemoryVault();
  const evidenceId = await saveSample(database);
  const before = structuredClone(database.stores.records.get(evidenceId));
  const details = await getCaseDetails(database, 'TEST-ONLY');

  expect(details.createdAt).toBe(before.createdAt);
  await saveCaseDetails(database, {
    ...details,
    title: 'Legacy case details',
    leadInvestigator: 'Investigator Two',
    description: 'Metadata added without changing evidence.',
  });

  expect(database.stores.records.get(evidenceId)).toEqual(before);
  await expect(getCases(database)).resolves.toContain('TEST-ONLY');
});

test('independently verifies decrypted evidence without changing stored bytes or custody', async () => {
  const database = createMemoryVault();
  const id = await saveSample(database);
  const [record] = await getCaseRecords(database, 'TEST-ONLY');
  const stored = database.stores.records.get(id);
  const ciphertextBefore = stored.file.ciphertext.slice(0);
  const custodyBefore = structuredClone(record.custody);

  const result = await verifyEvidenceIntegrity(database, id, record.sha256);

  expect(result).toMatchObject({
    status: 'MATCH',
    expectedSha256: expectedSha256,
    calculatedSha256: expectedSha256,
  });
  expect(Number.isNaN(Date.parse(result.verifiedAt))).toBe(false);
  expect(stored.file.ciphertext).toEqual(ciphertextBefore);
  const [after] = await getCaseRecords(database, 'TEST-ONLY');
  expect(after.sha256).toBe(record.sha256);
  expect(after.custody).toEqual(custodyBefore);
});

test('reports mismatched decrypted content and safely rejects corrupted or missing evidence', async () => {
  const database = createMemoryVault();
  const id = await saveSample(database);
  const key = database.stores.keys.get('evidence-encryption-key').key;
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const changedContents = encoder.encode('Changed harmless temporary sample.\n');
  database.stores.records.get(id).file = {
    iv: Array.from(iv),
    ciphertext: await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, changedContents),
  };

  const [record] = await getCaseRecords(database, 'TEST-ONLY');
  const mismatch = await verifyEvidenceIntegrity(database, id, record.sha256);
  expect(mismatch.status).toBe('MISMATCH');
  expect(mismatch.calculatedSha256).not.toBe(record.sha256);

  const stored = database.stores.records.get(id);
  const damagedCiphertext = stored.file.ciphertext.slice(0);
  new Uint8Array(damagedCiphertext)[0] ^= 0xff;
  stored.file.ciphertext = damagedCiphertext;
  await expect(verifyEvidenceIntegrity(database, id, record.sha256)).rejects.toThrow();
  await expect(verifyEvidenceIntegrity(database, 'missing-synthetic-record', record.sha256))
    .rejects.toThrow(/record was not found/i);
  database.stores.keys.delete('evidence-encryption-key');
  await expect(verifyEvidenceIntegrity(database, id, record.sha256))
    .rejects.toThrow(/decryption key was not found/i);
  expect(database.stores.keys.has('evidence-encryption-key')).toBe(false);
});

test('stores extracted EXIF data with encrypted evidence metadata', async () => {
  const database = createMemoryVault();
  const bytes = makeSampleExifJpeg();
  const file = {
    name: 'temporary-exif-sample.jpg',
    type: 'image/jpeg',
    size: bytes.byteLength,
    lastModified: 1_700_000_000_000,
    arrayBuffer: async () => bytes.slice().buffer,
  };

  await saveEvidence(database, {
    file,
    caseId: 'TEST-ONLY',
    custodian: 'Automated Test',
  });

  const [record] = await getCaseRecords(database, 'TEST-ONLY');
  expect(record.exif).toEqual({ cameraMake: 'Test' });
});

test('saves manual EXIF validation and references without changing evidence bytes or hash', async () => {
  const database = createMemoryVault();
  const id = await saveSample(database);
  const initialRecord = database.stores.records.get(id);
  const originalCiphertext = initialRecord.file.ciphertext.slice(0);
  const [before] = await getCaseRecords(database, 'TEST-ONLY');

  await saveExifValidation(database, id, {
    status: 'MISMATCH',
    analyst: '  Test Analyst  ',
    notes: '  Capture time differs from the reference report.  ',
    artifactReferences: [' LAB-REPORT-12 ', '', 'IMG-REF-03'],
  });

  const [after] = await getCaseRecords(database, 'TEST-ONLY');
  expect(after.sha256).toBe(before.sha256);
  expect(database.stores.records.get(id).file.ciphertext).toEqual(originalCiphertext);
  expect(after.exifValidation).toMatchObject({
    status: 'MISMATCH',
    analyst: 'Test Analyst',
    notes: 'Capture time differs from the reference report.',
    artifactReferences: ['LAB-REPORT-12', 'IMG-REF-03'],
  });
  expect(Date.parse(after.exifValidation.reviewedAt)).not.toBeNaN();
  expect(await verifyCustody(after.custody)).toBe(true);
  expect(after.custody.at(-1).action).toBe('EXIF validation: MISMATCH');
});

test('accepts each supported EXIF validation status and rejects unsupported statuses', async () => {
  const database = createMemoryVault();
  const id = await saveSample(database);

  for (const status of ['VERIFIED', 'NEEDS REVIEW']) {
    await saveExifValidation(database, id, {
      status,
      analyst: 'Test Analyst',
      notes: '',
      artifactReferences: [],
    });
    const [record] = await getCaseRecords(database, 'TEST-ONLY');
    expect(record.exifValidation.status).toBe(status);
  }
  await expect(saveExifValidation(database, id, {
    status: 'PENDING',
    analyst: 'Test Analyst',
    notes: '',
    artifactReferences: [],
  })).rejects.toThrow(/valid EXIF validation status/);
});

test('saves a registry analysis report and custody event without changing evidence', async () => {
  const database = createMemoryVault();
  const id = await saveSample(database);
  const sourceRecord = database.stores.records.get(id);
  const sourceCiphertext = sourceRecord.file.ciphertext.slice(0);
  const [before] = await getCaseRecords(database, 'TEST-ONLY');
  const report = {
    format: 'Windows Registry Hive (REGF)',
    hiveType: 'SOFTWARE',
    parsedAt: '2026-10-30T00:00:00.000Z',
    keyCount: 1,
    artifacts: [{ type: 'Startup command', keyPath: 'Software\\Run', values: [] }],
    warnings: [],
  };

  await saveRegistryAnalysis(database, id, {
    report,
    status: 'VERIFIED',
    analyst: 'Registry Analyst',
    notes: 'Reviewed test report.',
    artifactReferences: ['REF-100', ''],
  });

  const [after] = await getCaseRecords(database, 'TEST-ONLY');
  expect(after.sha256).toBe(before.sha256);
  expect(database.stores.records.get(id).file.ciphertext).toEqual(sourceCiphertext);
  expect(after.registryAnalysis).toMatchObject({
    report,
    status: 'VERIFIED',
    analyst: 'Registry Analyst',
    notes: 'Reviewed test report.',
    artifactReferences: ['REF-100'],
    sourceSha256: before.sha256,
  });
  expect(await verifyCustody(after.custody)).toBe(true);
  expect(after.custody.at(-1).action).toBe('Registry analysis report saved: VERIFIED');
});

test('saves PCAP analysis and validation without changing evidence hash or ciphertext', async () => {
  const database = createMemoryVault();
  const id = await saveSample(database);
  const evidenceCiphertext = database.stores.records.get(id).file.ciphertext.slice(0);
  const [before] = await getCaseRecords(database, 'TEST-ONLY');
  const report = {
    format: 'PCAP',
    parsedAt: '2026-10-30T00:00:00.000Z',
    packetCount: 1,
    nonIpPackets: 0,
    packets: [{ timestamp: '2026-10-30T00:00:00.000Z', sourceIp: '192.0.2.1', destinationIp: '198.51.100.2', sourcePort: 50000, destinationPort: 443, protocol: 'TCP', bytes: 60 }],
    packetDetailsTruncated: false,
    connectionCount: 1,
    connections: [{ protocol: 'TCP', endpointA: '192.0.2.1:50000', endpointB: '198.51.100.2:443', packets: 1, bytes: 60, firstSeen: '2026-10-30T00:00:00.000Z', lastSeen: '2026-10-30T00:00:00.000Z' }],
    leads: [{ indicator: 'Possible TCP port sweep pattern', classification: 'LEAD - NOT A CONFIRMED THREAT' }],
    warnings: [],
  };

  await savePcapAnalysis(database, id, {
    report,
    status: 'NEEDS REVIEW',
    analyst: 'Network Analyst',
    notes: 'Review the lead with other case evidence.',
    artifactReferences: ['NET-REF-01', ''],
  });

  const [after] = await getCaseRecords(database, 'TEST-ONLY');
  expect(after.sha256).toBe(before.sha256);
  expect(database.stores.records.get(id).file.ciphertext).toEqual(evidenceCiphertext);
  expect(after.pcapAnalysis).toMatchObject({
    report,
    status: 'NEEDS REVIEW',
    analyst: 'Network Analyst',
    notes: 'Review the lead with other case evidence.',
    artifactReferences: ['NET-REF-01'],
    sourceSha256: before.sha256,
  });
  expect(await verifyCustody(after.custody)).toBe(true);
  expect(after.custody.at(-1).action).toBe('PCAP analysis report saved: NEEDS REVIEW');
});

test('saves SQLite analysis metadata and custody without modifying source evidence', async () => {
  const database = createMemoryVault();
  const id = await saveSample(database);
  const sourceCiphertext = database.stores.records.get(id).file.ciphertext.slice(0);
  const [before] = await getCaseRecords(database, 'TEST-ONLY');
  const report = {
    format: 'SQLite Database',
    filename: 'temporary.sqlite',
    analyzedAt: '2026-10-30T00:00:00.000Z',
    userVersion: 1,
    tableCount: 1,
    viewCount: 0,
    recordCount: 1,
    recordsTruncated: false,
    tables: [{ name: 'events', type: 'table', columns: [], records: [], timestampFields: [] }],
    warnings: [],
  };

  await saveSqliteAnalysis(database, id, {
    report,
    status: 'VERIFIED',
    analyst: 'Database Analyst',
    notes: 'Reviewed harmless test fixture.',
    artifactReferences: ['DB-REF-2', ''],
  });

  const [after] = await getCaseRecords(database, 'TEST-ONLY');
  expect(after.sha256).toBe(before.sha256);
  expect(database.stores.records.get(id).file.ciphertext).toEqual(sourceCiphertext);
  expect(after.sqliteAnalysis).toMatchObject({
    report,
    status: 'VERIFIED',
    analyst: 'Database Analyst',
    notes: 'Reviewed harmless test fixture.',
    artifactReferences: ['DB-REF-2'],
    sourceSha256: before.sha256,
  });
  expect(await verifyCustody(after.custody)).toBe(true);
  expect(after.custody.at(-1).action).toBe('SQLite analysis report saved: VERIFIED');
});

test('saves Copilot suggestions as NEEDS REVIEW and records authorized human validation without changing evidence', async () => {
  const database = createMemoryVault();
  const id = await saveSample(database);
  const stored = database.stores.records.get(id);
  const evidenceCiphertext = stored.file.ciphertext.slice(0);
  const [before] = await getCaseRecords(database, 'TEST-ONLY');
  const finding = {
    id: 'temporary-finding-1',
    question: 'Explain the harmless test artifact.',
    observedEvidence: [{ caseId: 'TEST-ONLY', evidenceId: id, referenceId: 'E1', sha256: before.sha256, value: 'Harmless synthetic fact.' }],
    interpretations: [{ text: 'This may merit independent review.', evidenceRefs: ['E1'] }],
    investigativeLeads: [],
    recommendations: [],
    unsupportedClaims: [],
    validationStatus: 'NEEDS REVIEW',
    createdAt: '2026-10-30T12:00:00.000Z',
  };

  await saveCopilotFinding(database, id, finding);
  let [after] = await getCaseRecords(database, 'TEST-ONLY');
  expect(after.copilotFindings[0].validationStatus).toBe('NEEDS REVIEW');
  expect(await verifyCustody(after.custody)).toBe(true);
  expect(after.custody.at(-1).actor).toBe('AI Forensic Copilot');
  expect(stored.file.ciphertext).toEqual(evidenceCiphertext);
  expect(after.sha256).toBe(before.sha256);

  const validation = {
    status: 'VERIFIED',
    analyst: 'Authorized Test Investigator',
    investigatorId: 'synthetic-user-1',
    notes: 'Compared against the independent harmless fixture.',
    independentMethod: 'Separate offline test fixture review',
    authorized: true,
  };
  await expect(validateCopilotFinding(database, id, finding.id, { ...validation, authorized: false })).rejects.toThrow(/authorized investigator/i);
  await validateCopilotFinding(database, id, finding.id, validation);
  [after] = await getCaseRecords(database, 'TEST-ONLY');
  expect(after.copilotFindings[0].validationStatus).toBe('VERIFIED');
  expect(after.copilotFindings[0].validationHistory).toHaveLength(1);
  expect(after.copilotFindings[0].validationHistory[0]).toMatchObject({
    status: 'VERIFIED',
    analyst: 'Authorized Test Investigator',
    investigatorId: 'synthetic-user-1',
    independentMethod: 'Separate offline test fixture review',
  });
  expect(after.custody.at(-1).action).toBe('Copilot finding validation: VERIFIED');
  expect(await verifyCustody(after.custody)).toBe(true);
  expect(stored.file.ciphertext).toEqual(evidenceCiphertext);
  expect(after.sha256).toBe(before.sha256);
  expect(await readBlobText(await downloadEvidence(database, id))).toContain(sampleText.trim());
});

test('rejects decrypted evidence when its contents do not match the stored SHA-256', async () => {
  const database = createMemoryVault();
  const id = await saveSample(database);
  const key = database.stores.keys.get('evidence-encryption-key').key;
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const changedContents = encoder.encode('Changed harmless temporary sample.\n');
  database.stores.records.get(id).file = {
    iv: Array.from(iv),
    ciphertext: await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, changedContents),
  };

  await expect(downloadEvidence(database, id)).rejects.toThrow(/SHA-256 verification failed/);
});

test('verifies custody-chain links and rejects a modified event', async () => {
  const database = createMemoryVault();
  const id = await saveSample(database);
  await addCustodyEvent(database, id, 'Automated Test', 'Evidence reviewed');
  const [record] = await getCaseRecords(database, 'TEST-ONLY');

  expect(await verifyCustody(record.custody)).toBe(true);

  record.custody[1].action = 'Evidence altered';
  expect(await verifyCustody(record.custody)).toBe(false);
  expect(await verifyCustody([])).toBe(false);
});
