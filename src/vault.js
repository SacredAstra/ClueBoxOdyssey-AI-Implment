import { extractExifMetadata } from './exif';

const DATABASE_NAME = 'evidence-locker-private';
const DATABASE_VERSION = 2;
const KEY_ID = 'evidence-encryption-key';
const EXIF_VALIDATION_STATUSES = ['VERIFIED', 'MISMATCH', 'NEEDS REVIEW'];
const REGISTRY_VALIDATION_STATUSES = ['VERIFIED', 'MISMATCH', 'NEEDS REVIEW'];
const PCAP_VALIDATION_STATUSES = ['VERIFIED', 'MISMATCH', 'NEEDS REVIEW'];
const SQLITE_VALIDATION_STATUSES = ['VERIFIED', 'MISMATCH', 'NEEDS REVIEW'];
const COPILOT_VALIDATION_STATUSES = ['VERIFIED', 'MISMATCH', 'NEEDS REVIEW'];
const encoder = new TextEncoder();
const decoder = new TextDecoder();

export function openVault() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DATABASE_NAME, DATABASE_VERSION);
    request.onupgradeneeded = () => {
      const database = request.result;
      if (!database.objectStoreNames.contains('records')) {
        const records = database.createObjectStore('records', { keyPath: 'id' });
        records.createIndex('caseId', 'caseId', { unique: false });
      }
      if (!database.objectStoreNames.contains('keys')) {
        database.createObjectStore('keys', { keyPath: 'id' });
      }
      if (!database.objectStoreNames.contains('cases')) {
        database.createObjectStore('cases', { keyPath: 'caseId' });
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error || new Error('Could not open private browser storage.'));
  });
}

function requestResult(request) {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error || new Error('Browser storage request failed.'));
  });
}

function putRecord(database, storeName, value) {
  return new Promise((resolve, reject) => {
    const transaction = database.transaction(storeName, 'readwrite');
    const request = transaction.objectStore(storeName).put(value);
    let result;
    request.onsuccess = () => { result = request.result; };
    transaction.oncomplete = () => resolve(result);
    transaction.onerror = () => reject(transaction.error || new Error('Browser storage write failed.'));
    transaction.onabort = () => reject(transaction.error || new Error('Browser storage write was interrupted.'));
  });
}

function sameEncryptedValue(left, right) {
  if (!left || !right || JSON.stringify(left.iv) !== JSON.stringify(right.iv)) return false;
  const leftBytes = new Uint8Array(left.ciphertext);
  const rightBytes = new Uint8Array(right.ciphertext);
  return leftBytes.length === rightBytes.length && leftBytes.every((byte, index) => byte === rightBytes[index]);
}

function commitEvidenceMutation(database, originalRecord, expectedMetadata, newRecord = null) {
  return new Promise((resolve, reject) => {
    const transaction = database.transaction('records', 'readwrite');
    const store = transaction.objectStore('records');
    let failure;
    transaction.oncomplete = () => resolve();
    transaction.onerror = () => reject(failure || transaction.error || new Error('Evidence records could not be updated.'));
    transaction.onabort = () => reject(failure || transaction.error || new Error('Evidence record update was interrupted.'));
    const request = store.get(originalRecord.id);
    request.onsuccess = () => {
      if (!request.result || !sameEncryptedValue(request.result.metadata, expectedMetadata)) {
        failure = new Error('Evidence changed during this action. Reload the case and review the record before retrying.');
        transaction.abort();
        return;
      }
      store.put(originalRecord);
      if (newRecord) store.add(newRecord);
    };
  });
}

async function getEncryptionKey(database) {
  const stored = await requestResult(database.transaction('keys', 'readonly').objectStore('keys').get(KEY_ID));
  if (stored?.key) return stored.key;
  const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  await putRecord(database, 'keys', { id: KEY_ID, key });
  return key;
}

async function encryptBytes(key, bytes) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, bytes);
  return { iv: Array.from(iv), ciphertext };
}

async function decryptBytes(key, encrypted) {
  return crypto.subtle.decrypt({ name: 'AES-GCM', iv: new Uint8Array(encrypted.iv) }, key, encrypted.ciphertext);
}

async function hashHex(bytes) {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
  return Array.from(digest, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function makeEventHash({ timestamp, actor, action, previousHash, details }) {
  const serializedDetails = details === undefined ? '' : `|${JSON.stringify(details)}`;
  return hashHex(encoder.encode(`${timestamp}|${actor}|${action}|${previousHash}${serializedDetails}`));
}

async function createCustodyEvent(custody, actor, action, details, timestamp = new Date().toISOString()) {
  const event = {
    timestamp,
    actor,
    action,
    previousHash: custody.at(-1)?.eventHash || 'GENESIS',
  };
  if (details) event.details = details;
  event.eventHash = await makeEventHash(event);
  return event;
}

async function extractMediaMetadata(file) {
  if (file.type.startsWith('image/')) {
    try {
      const bitmap = await createImageBitmap(file);
      const dimensions = `${bitmap.width} × ${bitmap.height} px`;
      bitmap.close();
      return { dimensions };
    } catch {
      return {};
    }
  }
  if (file.type.startsWith('audio/') || file.type.startsWith('video/')) {
    const element = document.createElement(file.type.startsWith('audio/') ? 'audio' : 'video');
    const url = URL.createObjectURL(file);
    const media = await new Promise((resolve) => {
      const finish = (result) => resolve(result);
      element.onloadedmetadata = () => finish({
        dimensions: element.videoWidth && element.videoHeight ? `${element.videoWidth} × ${element.videoHeight} px` : undefined,
        duration: Number.isFinite(element.duration) ? `${Math.floor(element.duration / 60)}:${String(Math.floor(element.duration % 60)).padStart(2, '0')}` : undefined,
      });
      element.onerror = () => finish({});
      element.src = url;
    });
    URL.revokeObjectURL(url);
    element.removeAttribute('src');
    return media;
  }
  if (file.type === 'application/pdf' || file.name.toLowerCase().endsWith('.pdf')) {
    const header = decoder.decode(await file.slice(0, 16).arrayBuffer());
    const version = header.match(/%PDF-(\d\.\d)/)?.[1];
    return version ? { pdfVersion: version } : {};
  }
  return {};
}

export async function saveEvidence(database, { file, caseId, custodian }) {
  const key = await getEncryptionKey(database);
  const fileBytes = await file.arrayBuffer();
  const metadata = {
    name: file.name,
    type: file.type,
    size: file.size,
    lastModified: file.lastModified ? new Date(file.lastModified).toISOString() : new Date().toISOString(),
    sha256: await hashHex(fileBytes),
    exif: extractExifMetadata(fileBytes),
    ...await extractMediaMetadata(file),
    custody: [],
  };
  metadata.custody.push(await createCustodyEvent([], custodian, 'Evidence received'));
  const [encryptedFile, encryptedMetadata] = await Promise.all([
    encryptBytes(key, fileBytes),
    encryptBytes(key, encoder.encode(JSON.stringify(metadata))),
  ]);
  const id = crypto.randomUUID();
  const record = { id, caseId, createdAt: new Date().toISOString(), file: encryptedFile, metadata: encryptedMetadata };
  await putRecord(database, 'records', record);
  return id;
}

function validateEvidenceDisposition({ analyst, reason }) {
  if (typeof analyst !== 'string' || !analyst.trim() || analyst.trim().length > 200) {
    throw new Error('Enter the analyst name (up to 200 characters).');
  }
  if (typeof reason !== 'string' || !reason.trim() || reason.trim().length > 5000) {
    throw new Error('Enter a reason (up to 5,000 characters).');
  }
}

async function readRecordAndMetadata(database, id) {
  const record = await requestResult(database.transaction('records', 'readonly').objectStore('records').get(id));
  if (!record) throw new Error('Evidence record was not found.');
  const key = await getEncryptionKey(database);
  const metadata = JSON.parse(decoder.decode(await decryptBytes(key, record.metadata)));
  if (!Array.isArray(metadata.custody) || !metadata.custody.length) {
    throw new Error('Evidence custody history is missing or invalid; the record was not changed.');
  }
  return { record, metadata, key };
}

function assertEvidenceIsActive(metadata) {
  if (metadata.archivedAt) {
    throw new Error('Archived evidence is read-only and cannot receive new analysis or custody changes.');
  }
}

export async function archiveEvidenceRecord(database, id, { analyst, reason, userId = null } = {}) {
  validateEvidenceDisposition({ analyst, reason });
  const { record, metadata, key } = await readRecordAndMetadata(database, id);
  if (metadata.archivedAt) throw new Error('Evidence is already archived.');

  const expectedMetadata = record.metadata;
  const timestamp = new Date().toISOString();
  const normalizedAnalyst = analyst.trim();
  const normalizedReason = reason.trim();
  const details = {
    action: 'remove_from_case',
    analyst: normalizedAnalyst,
    userId,
    reason: normalizedReason,
    originalEvidenceId: id,
    replacementEvidenceId: null,
  };
  metadata.archivedAt = timestamp;
  metadata.archive = {
    action: 'removed',
    analyst: normalizedAnalyst,
    userId,
    reason: normalizedReason,
    originalEvidenceId: id,
    replacementEvidenceId: null,
  };
  metadata.custody.push(await createCustodyEvent(
    metadata.custody,
    normalizedAnalyst,
    'Evidence removed from case',
    details,
    timestamp,
  ));
  record.metadata = await encryptBytes(key, encoder.encode(JSON.stringify(metadata)));
  await commitEvidenceMutation(database, record, expectedMetadata);
  return { id, archivedAt: timestamp };
}

export async function replaceEvidence(database, originalId, { file, analyst, reason, userId = null } = {}) {
  validateEvidenceDisposition({ analyst, reason });
  if (!file || typeof file.arrayBuffer !== 'function') {
    throw new Error('Choose a replacement evidence file.');
  }
  const { record: originalRecord, metadata: originalMetadata, key } = await readRecordAndMetadata(database, originalId);
  if (originalMetadata.archivedAt) throw new Error('Archived evidence cannot be replaced.');

  const expectedMetadata = originalRecord.metadata;
  const timestamp = new Date().toISOString();
  const normalizedAnalyst = analyst.trim();
  const normalizedReason = reason.trim();
  const replacementId = crypto.randomUUID();
  const details = {
    action: 'replace_evidence',
    analyst: normalizedAnalyst,
    userId,
    reason: normalizedReason,
    originalEvidenceId: originalId,
    replacementEvidenceId: replacementId,
  };
  const fileBytes = await file.arrayBuffer();
  const replacementMetadata = {
    name: file.name,
    type: file.type,
    size: file.size,
    lastModified: file.lastModified ? new Date(file.lastModified).toISOString() : timestamp,
    sha256: await hashHex(fileBytes),
    exif: extractExifMetadata(fileBytes),
    ...await extractMediaMetadata(file),
    custody: [],
    replacement: {
      originalEvidenceId: originalId,
      replacedAt: timestamp,
      analyst: normalizedAnalyst,
      userId,
      reason: normalizedReason,
    },
  };
  replacementMetadata.custody.push(await createCustodyEvent(
    [],
    normalizedAnalyst,
    'Evidence received as replacement',
    details,
    timestamp,
  ));
  const [replacementFile, encryptedReplacementMetadata] = await Promise.all([
    encryptBytes(key, fileBytes),
    encryptBytes(key, encoder.encode(JSON.stringify(replacementMetadata))),
  ]);
  const replacementRecord = {
    id: replacementId,
    caseId: originalRecord.caseId,
    createdAt: timestamp,
    file: replacementFile,
    metadata: encryptedReplacementMetadata,
  };

  originalMetadata.archivedAt = timestamp;
  originalMetadata.archive = {
    action: 'replaced',
    analyst: normalizedAnalyst,
    userId,
    reason: normalizedReason,
    originalEvidenceId: originalId,
    replacementEvidenceId: replacementId,
  };
  originalMetadata.replacementEvidenceId = replacementId;
  originalMetadata.custody.push(await createCustodyEvent(
    originalMetadata.custody,
    normalizedAnalyst,
    'Evidence replaced',
    details,
    timestamp,
  ));
  originalRecord.metadata = await encryptBytes(key, encoder.encode(JSON.stringify(originalMetadata)));

  await commitEvidenceMutation(database, originalRecord, expectedMetadata, replacementRecord);
  return replacementId;
}

export async function getCaseRecords(database, caseId) {
  const key = await getEncryptionKey(database);
  const storedRecords = await requestResult(database.transaction('records', 'readonly').objectStore('records').index('caseId').getAll(caseId));
  const records = await Promise.all(storedRecords.map(async (record) => {
    const metadataBytes = await decryptBytes(key, record.metadata);
    return { id: record.id, caseId: record.caseId, createdAt: record.createdAt, ...JSON.parse(decoder.decode(metadataBytes)) };
  }));
  return records.sort((left, right) => right.createdAt.localeCompare(left.createdAt));
}

export async function getCases(database) {
  const storedRecords = await requestResult(database.transaction('records', 'readonly').objectStore('records').getAll());
  const storedCases = await requestResult(database.transaction('cases', 'readonly').objectStore('cases').getAll());
  return [...new Set([
    ...storedRecords.map((record) => record.caseId),
    ...storedCases.map((record) => record.caseId),
  ])].sort();
}

export async function getCaseDetails(database, caseId) {
  const stored = await requestResult(database.transaction('cases', 'readonly').objectStore('cases').get(caseId));
  if (stored?.details) {
    const key = await getEncryptionKey(database);
    return JSON.parse(decoder.decode(await decryptBytes(key, stored.details)));
  }
  const records = await requestResult(database.transaction('records', 'readonly').objectStore('records').index('caseId').getAll(caseId));
  const createdAt = records.reduce(
    (earliest, record) => record.createdAt < earliest ? record.createdAt : earliest,
    records[0]?.createdAt || new Date().toISOString(),
  );
  return {
    caseId,
    title: '',
    leadInvestigator: '',
    description: '',
    status: 'Open',
    createdAt,
    updatedAt: createdAt,
  };
}

export async function saveCaseDetails(database, caseDetails) {
  const { caseId, title, leadInvestigator, description, status } = caseDetails;
  if (typeof caseId !== 'string' || !caseId.trim()) throw new Error('A case ID is required.');
  if (typeof title !== 'string' || typeof leadInvestigator !== 'string' || typeof description !== 'string') {
    throw new Error('Enter valid case details before saving.');
  }
  if (title.length > 200 || leadInvestigator.length > 200 || description.length > 10000) {
    throw new Error('Case details exceed the allowed length.');
  }
  if (!['Open', 'In Progress', 'Under Review', 'Closed'].includes(status)) {
    throw new Error('Choose a valid case status.');
  }

  const stored = await requestResult(database.transaction('cases', 'readonly').objectStore('cases').get(caseId));
  const existing = await getCaseDetails(database, caseId);
  const requestedCreatedAt = typeof caseDetails.createdAt === 'string' && !Number.isNaN(Date.parse(caseDetails.createdAt))
    ? caseDetails.createdAt
    : existing.createdAt;
  const details = {
    caseId,
    title: title.trim(),
    leadInvestigator: leadInvestigator.trim(),
    description: description.trim(),
    status,
    createdAt: stored?.details ? existing.createdAt : requestedCreatedAt,
    updatedAt: new Date().toISOString(),
  };
  const key = await getEncryptionKey(database);
  await putRecord(database, 'cases', {
    caseId,
    details: await encryptBytes(key, encoder.encode(JSON.stringify(details))),
  });
  return details;
}

export async function addCustodyEvent(database, id, actor, action) {
  const record = await requestResult(database.transaction('records', 'readonly').objectStore('records').get(id));
  if (!record) throw new Error('Evidence record was not found.');
  const key = await getEncryptionKey(database);
  const metadata = JSON.parse(decoder.decode(await decryptBytes(key, record.metadata)));
  assertEvidenceIsActive(metadata);
  metadata.custody.push(await createCustodyEvent(metadata.custody, actor, action));
  record.metadata = await encryptBytes(key, encoder.encode(JSON.stringify(metadata)));
  await putRecord(database, 'records', record);
}

export async function saveExifValidation(database, id, validation) {
  const { status, analyst, notes, artifactReferences } = validation;
  if (!EXIF_VALIDATION_STATUSES.includes(status)) {
    throw new Error('Choose a valid EXIF validation status.');
  }
  if (typeof analyst !== 'string' || !analyst.trim()) {
    throw new Error('Enter the analyst name before saving EXIF validation.');
  }
  if (typeof notes !== 'string' || !Array.isArray(artifactReferences)
    || artifactReferences.some((reference) => typeof reference !== 'string')) {
    throw new Error('Enter valid EXIF validation notes and artifact references.');
  }
  const record = await requestResult(database.transaction('records', 'readonly').objectStore('records').get(id));
  if (!record) throw new Error('Evidence record was not found.');
  const key = await getEncryptionKey(database);
  const metadata = JSON.parse(decoder.decode(await decryptBytes(key, record.metadata)));
  assertEvidenceIsActive(metadata);
  const savedValidation = {
    status,
    analyst: analyst.trim(),
    notes: notes.trim(),
    artifactReferences: artifactReferences.map((reference) => reference.trim()).filter(Boolean),
    reviewedAt: new Date().toISOString(),
  };
  metadata.exifValidation = savedValidation;
  metadata.custody.push(await createCustodyEvent(metadata.custody, savedValidation.analyst, `EXIF validation: ${status}`));
  record.metadata = await encryptBytes(key, encoder.encode(JSON.stringify(metadata)));
  await putRecord(database, 'records', record);
}

export async function saveRegistryAnalysis(database, id, analysis) {
  const { report, status, analyst, notes, artifactReferences } = analysis;
  if (!report || report.format !== 'Windows Registry Hive (REGF)' || !Array.isArray(report.artifacts)) {
    throw new Error('Analyze a supported registry hive before saving its report.');
  }
  if (!REGISTRY_VALIDATION_STATUSES.includes(status)) {
    throw new Error('Choose a valid registry analysis status.');
  }
  if (typeof analyst !== 'string' || !analyst.trim()) {
    throw new Error('Enter the analyst name before saving the registry report.');
  }
  if (typeof notes !== 'string' || !Array.isArray(artifactReferences)
    || artifactReferences.some((reference) => typeof reference !== 'string')) {
    throw new Error('Enter valid registry analysis notes and artifact references.');
  }
  const record = await requestResult(database.transaction('records', 'readonly').objectStore('records').get(id));
  if (!record) throw new Error('Evidence record was not found.');
  const key = await getEncryptionKey(database);
  const metadata = JSON.parse(decoder.decode(await decryptBytes(key, record.metadata)));
  assertEvidenceIsActive(metadata);
  const savedAnalysis = {
    report,
    status,
    analyst: analyst.trim(),
    notes: notes.trim(),
    artifactReferences: artifactReferences.map((reference) => reference.trim()).filter(Boolean),
    reviewedAt: new Date().toISOString(),
    sourceSha256: metadata.sha256,
  };
  metadata.registryAnalysis = savedAnalysis;
  metadata.custody.push(await createCustodyEvent(
    metadata.custody,
    savedAnalysis.analyst,
    `Registry analysis report saved: ${status}`,
  ));
  record.metadata = await encryptBytes(key, encoder.encode(JSON.stringify(metadata)));
  await putRecord(database, 'records', record);
}

export async function savePcapAnalysis(database, id, analysis) {
  const { report, status, analyst, notes, artifactReferences } = analysis;
  if (!report || !['PCAP', 'PCAPNG'].includes(report.format)
    || !Array.isArray(report.packets) || !Array.isArray(report.connections) || !Array.isArray(report.leads)) {
    throw new Error('Analyze a supported PCAP or PCAPNG capture before saving its report.');
  }
  if (!PCAP_VALIDATION_STATUSES.includes(status)) {
    throw new Error('Choose a valid PCAP analysis status.');
  }
  if (typeof analyst !== 'string' || !analyst.trim()) {
    throw new Error('Enter the analyst name before saving the PCAP report.');
  }
  if (typeof notes !== 'string' || !Array.isArray(artifactReferences)
    || artifactReferences.some((reference) => typeof reference !== 'string')) {
    throw new Error('Enter valid PCAP analysis notes and artifact references.');
  }
  const record = await requestResult(database.transaction('records', 'readonly').objectStore('records').get(id));
  if (!record) throw new Error('Evidence record was not found.');
  const key = await getEncryptionKey(database);
  const metadata = JSON.parse(decoder.decode(await decryptBytes(key, record.metadata)));
  assertEvidenceIsActive(metadata);
  const savedAnalysis = {
    report,
    status,
    analyst: analyst.trim(),
    notes: notes.trim(),
    artifactReferences: artifactReferences.map((reference) => reference.trim()).filter(Boolean),
    reviewedAt: new Date().toISOString(),
    sourceSha256: metadata.sha256,
  };
  metadata.pcapAnalysis = savedAnalysis;
  metadata.custody.push(await createCustodyEvent(
    metadata.custody,
    savedAnalysis.analyst,
    `PCAP analysis report saved: ${status}`,
  ));
  record.metadata = await encryptBytes(key, encoder.encode(JSON.stringify(metadata)));
  await putRecord(database, 'records', record);
}

export async function saveSqliteAnalysis(database, id, analysis) {
  const { report, status, analyst, notes, artifactReferences } = analysis;
  if (!report || report.format !== 'SQLite Database' || !Array.isArray(report.tables)) {
    throw new Error('Analyze a supported SQLite database before saving its report.');
  }
  if (!SQLITE_VALIDATION_STATUSES.includes(status)) {
    throw new Error('Choose a valid SQLite analysis status.');
  }
  if (typeof analyst !== 'string' || !analyst.trim()) {
    throw new Error('Enter the analyst name before saving the SQLite report.');
  }
  if (typeof notes !== 'string' || !Array.isArray(artifactReferences)
    || artifactReferences.some((reference) => typeof reference !== 'string')) {
    throw new Error('Enter valid SQLite analysis notes and artifact references.');
  }
  const record = await requestResult(database.transaction('records', 'readonly').objectStore('records').get(id));
  if (!record) throw new Error('Evidence record was not found.');
  const key = await getEncryptionKey(database);
  const metadata = JSON.parse(decoder.decode(await decryptBytes(key, record.metadata)));
  assertEvidenceIsActive(metadata);
  const savedAnalysis = {
    report,
    status,
    analyst: analyst.trim(),
    notes: notes.trim(),
    artifactReferences: artifactReferences.map((reference) => reference.trim()).filter(Boolean),
    reviewedAt: new Date().toISOString(),
    sourceSha256: metadata.sha256,
  };
  metadata.sqliteAnalysis = savedAnalysis;
  metadata.custody.push(await createCustodyEvent(
    metadata.custody,
    savedAnalysis.analyst,
    `SQLite analysis report saved: ${status}`,
  ));
  record.metadata = await encryptBytes(key, encoder.encode(JSON.stringify(metadata)));
  await putRecord(database, 'records', record);
}

export async function saveCopilotFinding(database, id, finding) {
  if (!finding || typeof finding.id !== 'string' || !finding.id
    || typeof finding.question !== 'string' || finding.question.trim().length > 2_000
    || finding.validationStatus !== 'NEEDS REVIEW'
    || !Array.isArray(finding.observedEvidence) || finding.observedEvidence.length < 1 || finding.observedEvidence.length > 100
    || !Array.isArray(finding.interpretations) || finding.interpretations.length > 30
    || !Array.isArray(finding.investigativeLeads) || finding.investigativeLeads.length > 30
    || !Array.isArray(finding.recommendations) || finding.recommendations.length > 30
    || !Array.isArray(finding.unsupportedClaims) || finding.unsupportedClaims.length > 100) {
    throw new Error('Only a structured, unverified Copilot finding can be saved.');
  }
  const record = await requestResult(database.transaction('records', 'readonly').objectStore('records').get(id));
  if (!record) throw new Error('Evidence record was not found.');
  const key = await getEncryptionKey(database);
  const metadata = JSON.parse(decoder.decode(await decryptBytes(key, record.metadata)));
  assertEvidenceIsActive(metadata);
  const caseRecords = await getCaseRecords(database, record.caseId);
  const sourceRecords = new Map(caseRecords.map((item) => [item.id, item]));
  if (!finding.observedEvidence.every((fact) => fact.caseId === record.caseId
    && !sourceRecords.get(fact.evidenceId)?.archivedAt
    && sourceRecords.get(fact.evidenceId)?.sha256 === fact.sha256)) {
    throw new Error('Copilot finding evidence must belong to this case and match its current SHA-256.');
  }
  const knownReferences = new Set(finding.observedEvidence.map((fact) => fact.referenceId));
  for (const claim of [...finding.interpretations, ...finding.investigativeLeads, ...finding.recommendations]) {
    if (typeof claim?.text !== 'string' || claim.text.length > 1_000
      || !Array.isArray(claim.evidenceRefs) || !claim.evidenceRefs.length
      || claim.evidenceRefs.some((reference) => !knownReferences.has(reference))) {
      throw new Error('Copilot findings must contain only claims supported by saved evidence references.');
    }
  }
  const existing = metadata.copilotFindings || [];
  if (existing.some((saved) => saved.id === finding.id)) throw new Error('This Copilot finding has already been saved.');
  metadata.copilotFindings = [...existing, {
    ...finding,
    validationHistory: [],
    validationStatus: 'NEEDS REVIEW',
  }];
  metadata.custody.push(await createCustodyEvent(
    metadata.custody,
    'AI Forensic Copilot',
    `AI finding saved for human review (${finding.observedEvidence.length} evidence facts)`,
  ));
  record.metadata = await encryptBytes(key, encoder.encode(JSON.stringify(metadata)));
  await putRecord(database, 'records', record);
}

export async function validateCopilotFinding(database, id, findingId, validation) {
  const { status, analyst, investigatorId, notes, independentMethod, authorized } = validation || {};
  if (!authorized || !COPILOT_VALIDATION_STATUSES.includes(status)) {
    throw new Error('An authorized investigator must select a valid finding status.');
  }
  if (typeof analyst !== 'string' || !analyst.trim() || typeof investigatorId !== 'string' || !investigatorId.trim()) {
    throw new Error('An authenticated investigator identity is required.');
  }
  if (typeof notes !== 'string' || !notes.trim() || typeof independentMethod !== 'string' || !independentMethod.trim()) {
    throw new Error('Analyst notes and an independent verification method are required.');
  }
  const record = await requestResult(database.transaction('records', 'readonly').objectStore('records').get(id));
  if (!record) throw new Error('Evidence record was not found.');
  const key = await getEncryptionKey(database);
  const metadata = JSON.parse(decoder.decode(await decryptBytes(key, record.metadata)));
  assertEvidenceIsActive(metadata);
  const findings = metadata.copilotFindings || [];
  const finding = findings.find((saved) => saved.id === findingId);
  if (!finding) throw new Error('Copilot finding was not found.');
  const validationEntry = {
    status,
    analyst: analyst.trim(),
    investigatorId: investigatorId.trim(),
    notes: notes.trim(),
    independentMethod: independentMethod.trim(),
    reviewedAt: new Date().toISOString(),
  };
  finding.validationHistory = [...(finding.validationHistory || []), validationEntry];
  finding.validationStatus = status;
  metadata.copilotFindings = findings;
  metadata.custody.push(await createCustodyEvent(
    metadata.custody,
    analyst.trim(),
    `Copilot finding validation: ${status}`,
  ));
  record.metadata = await encryptBytes(key, encoder.encode(JSON.stringify(metadata)));
  await putRecord(database, 'records', record);
}

export async function downloadEvidence(database, id) {
  const record = await requestResult(database.transaction('records', 'readonly').objectStore('records').get(id));
  if (!record) throw new Error('Evidence record was not found.');
  const key = await getEncryptionKey(database);
  const bytes = await decryptBytes(key, record.file);
  const metadata = JSON.parse(decoder.decode(await decryptBytes(key, record.metadata)));
  if (await hashHex(bytes) !== metadata.sha256) throw new Error('SHA-256 verification failed. The evidence was not released.');
  return new Blob([bytes], { type: metadata.type || 'application/octet-stream' });
}

export async function verifyEvidenceIntegrity(database, id, expectedSha256) {
  const record = await requestResult(database.transaction('records', 'readonly').objectStore('records').get(id));
  if (!record) throw new Error('Evidence record was not found.');
  const storedKey = await requestResult(database.transaction('keys', 'readonly').objectStore('keys').get(KEY_ID));
  if (!storedKey?.key) throw new Error('Evidence decryption key was not found.');
  const key = storedKey.key;
  const [fileBytes, metadataBytes] = await Promise.all([
    decryptBytes(key, record.file),
    decryptBytes(key, record.metadata),
  ]);
  const metadata = JSON.parse(decoder.decode(metadataBytes));
  const calculatedSha256 = await hashHex(fileBytes);
  const recordedSha256 = typeof metadata.sha256 === 'string' ? metadata.sha256.toLowerCase() : '';
  const expected = typeof expectedSha256 === 'string' ? expectedSha256.toLowerCase() : '';
  const status = calculatedSha256 === recordedSha256 && calculatedSha256 === expected ? 'MATCH' : 'MISMATCH';

  return {
    status,
    verifiedAt: new Date().toISOString(),
    expectedSha256,
    calculatedSha256,
  };
}

export async function verifyCustody(custody) {
  let previousHash = 'GENESIS';
  for (const entry of custody) {
    if (entry.previousHash !== previousHash || await makeEventHash(entry) !== entry.eventHash) return false;
    previousHash = entry.eventHash;
  }
  return custody.length > 0;
}
