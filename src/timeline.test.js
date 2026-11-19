import { expect, test } from 'vitest';
import {
  createInvestigationReport,
  createTimelineEvents,
  filterTimelineEvents,
  normalizeTimelineTimestamp,
  timelineToCsv,
} from './timeline';

const caseId = 'SYNTHETIC-CASE';
const fixture = {
  id: 'synthetic-evidence-1',
  caseId,
  name: 'harmless-temporary-fixture.bin',
  type: 'application/octet-stream',
  size: 12,
  createdAt: '2026-10-30T12:00:00.000Z',
  sha256: 'a'.repeat(64),
  exif: {
    capturedAt: '2026:10:30 10:11:12',
    digitizedAt: '2026-10-30T10:11:12-04:00',
    modifiedAt: 'not-a-real-date',
  },
  exifValidation: { status: 'NEEDS REVIEW', analyst: 'Synthetic Analyst', reviewedAt: '2026-10-30T13:00:00Z' },
  registryAnalysis: {
    status: 'VERIFIED',
    report: {
      artifacts: [
        { type: 'Installed application', keyPath: 'Software\\Example', values: [{ name: 'InstallDate', data: '20261030' }] },
        { type: 'Startup command', keyPath: 'Software\\Run', values: [{ name: 'Command', data: 'C:\\sample.exe' }] },
      ],
      warnings: [],
    },
    artifactReferences: ['REG-REF-01'],
  },
  pcapAnalysis: {
    status: 'NEEDS REVIEW',
    report: {
      packets: [{
        timestamp: '2026-10-30T14:00:00.000Z',
        originalTimestamp: { seconds: 1_793_368_800, fraction: 0, resolution: 0.000001 },
        sourceIp: '192.0.2.10',
        destinationIp: '198.51.100.20',
        sourcePort: 50000,
        destinationPort: 443,
        protocol: 'TCP',
        bytes: 60,
      }],
      connections: [{
        protocol: 'TCP',
        endpointA: '192.0.2.10:50000',
        endpointB: '198.51.100.20:443',
        packets: 1,
        bytes: 60,
        firstSeen: '2026-10-30T14:00:00.000Z',
        lastSeen: '2026-10-30T14:00:01.000Z',
      }],
      leads: [{ indicator: 'Synthetic suspicious-pattern lead', note: 'Requires analyst review.' }],
      warnings: [],
    },
    artifactReferences: ['PCAP-REF-01'],
  },
  sqliteAnalysis: {
    status: 'MISMATCH',
    report: {
      tables: [{
        name: 'activity',
        timestampFields: [{
          column: 'created_at',
          examples: [
            { raw: 1_798_900_800, iso: '2027-01-02T14:40:00.000Z', reason: 'Unix seconds' },
            { raw: '1798900800', iso: '2027-01-02T14:40:00.000Z', reason: 'Unix seconds' },
            { raw: '2026-10-30 09:00:00', iso: '2026-10-30T09:00:00.000Z', reason: 'Date/time text' },
          ],
        }],
      }],
      warnings: [],
    },
  },
  custody: [{
    timestamp: '2026-10-30T11:00:00.000Z',
    actor: 'Synthetic Custodian',
    action: 'Evidence received',
    previousHash: 'GENESIS',
    eventHash: 'b'.repeat(64),
  }],
  copilotFindings: [{
    id: 'synthetic-finding-1',
    question: 'Explain the synthetic artifact.',
    createdAt: '2026-10-30T15:00:00Z',
    validationStatus: 'NEEDS REVIEW',
    observedEvidence: [{ evidenceId: 'synthetic-evidence-1', artifactReference: 'Software\\Example' }],
    interpretations: [{ text: 'It may warrant review.', evidenceRefs: ['E2'] }],
    investigativeLeads: [{ text: 'Compare with another source.', evidenceRefs: ['E2'] }],
    unsupportedClaims: [{ text: 'Unsupported synthetic claim.' }],
    validationHistory: [{
      status: 'VERIFIED',
      analyst: 'Authorized Synthetic Investigator',
      independentMethod: 'Separate synthetic fixture comparison',
      reviewedAt: '2026-10-30T16:00:00Z',
    }],
  }],
};

test('normalizes only explicit offsets and reliable Unix epoch timestamps to UTC', () => {
  expect(normalizeTimelineTimestamp('2026-10-30T10:00:00-04:00')).toMatchObject({
    normalizedTimestamp: '2026-10-30T14:00:00.000Z',
    originalTimestamp: '2026-10-30T10:00:00-04:00',
    timeZone: 'UTC-04:00',
    timestampStatus: 'NORMALIZED UTC',
  });
  expect(normalizeTimelineTimestamp(1_798_900_800, { allowUnixEpoch: true })).toMatchObject({
    normalizedTimestamp: '2027-01-02T14:40:00.000Z',
    timeZone: 'UTC (Unix epoch)',
  });
  expect(normalizeTimelineTimestamp(1_798_900_800, {
    allowUnixEpoch: true,
    originalTimestamp: '1798900800',
  })).toMatchObject({
    normalizedTimestamp: '2027-01-02T14:40:00.000Z',
    originalTimestamp: '1798900800',
  });
  expect(normalizeTimelineTimestamp('2026:10:30 10:11:12')).toMatchObject({
    normalizedTimestamp: null,
    timeZone: 'Unknown (source did not provide an offset)',
    timestampStatus: 'AMBIGUOUS — TIME ZONE UNKNOWN',
  });
  expect(normalizeTimelineTimestamp('2026-10-30')).toMatchObject({
    normalizedTimestamp: null,
    timestampStatus: 'AMBIGUOUS DATE — TIME NOT PROVIDED',
  });
  expect(normalizeTimelineTimestamp('2026-02-31T12:00:00Z').timestampStatus).toBe('INVALID');
});

test('extracts EXIF, Registry, PCAP, SQLite, custody, and AI validation events with references', () => {
  const events = createTimelineEvents(caseId, [fixture], { [fixture.id]: { custody: true } });
  const modules = new Set(events.map((event) => event.sourceModule));
  for (const module of ['EXIF', 'Windows Registry', 'PCAP', 'SQLite', 'Chain of custody', 'Human validation', 'AI Forensic Copilot']) {
    expect(modules.has(module), `missing ${module}`).toBe(true);
  }
  const exifDate = events.find((event) => event.artifactReference === 'EXIF DateTimeOriginal');
  expect(exifDate).toMatchObject({
    caseId,
    evidenceId: fixture.id,
    originalTimestamp: fixture.exif.capturedAt,
    timestamp: null,
    timestampStatus: 'AMBIGUOUS — TIME ZONE UNKNOWN',
    validationStatus: 'NEEDS REVIEW',
  });
  expect(events.find((event) => event.sourceModule === 'Windows Registry')).toMatchObject({
    artifactReference: 'Software\\Example / InstallDate',
    originalTimestamp: '20261030',
    timestamp: null,
  });
  expect(events.find((event) => event.sourceModule === 'PCAP' && event.artifactReference === 'Packet 1')).toMatchObject({
    timestamp: '2026-10-30T14:00:00.000Z',
    originalTimestamp: { seconds: 1_793_368_800, fraction: 0, resolution: 0.000001 },
    timeZone: 'UTC (Z)',
  });
  expect(events.find((event) => event.sourceModule === 'SQLite' && event.originalTimestamp === 1_798_900_800).timestamp).toBe('2027-01-02T14:40:00.000Z');
  expect(events.find((event) => event.sourceModule === 'SQLite' && event.originalTimestamp === '1798900800').timestamp).toBe('2027-01-02T14:40:00.000Z');
  expect(events.find((event) => event.sourceModule === 'Chain of custody').validationStatus).toBe('VERIFIED');
  expect(events.find((event) => event.sourceModule === 'PCAP' && event.artifactReference === 'Network lead 1')).toMatchObject({
    timestamp: null,
    validationStatus: 'NEEDS REVIEW',
    classification: 'UNVERIFIED / NEEDS REVIEW',
  });
  expect(events.find((event) => event.sourceModule === 'Human validation')).toMatchObject({
    validationStatus: 'NEEDS REVIEW',
    classification: 'UNVERIFIED / NEEDS REVIEW',
  });
});

test('orders normalized events chronologically and keeps unresolved timestamp events separately', () => {
  const events = createTimelineEvents(caseId, [fixture]);
  const timed = events.filter((event) => event.timestamp);
  const untimed = events.filter((event) => !event.timestamp);
  expect(timed.length).toBeGreaterThan(0);
  expect(untimed.length).toBeGreaterThan(0);
  expect(timed.map((event) => event.timestamp)).toEqual([...timed.map((event) => event.timestamp)].sort());
  expect(events.slice(0, timed.length).every((event) => event.timestamp)).toBe(true);
  expect(events.slice(timed.length).every((event) => !event.timestamp)).toBe(true);
  expect(createTimelineEvents('OTHER-CASE', [fixture])).toEqual([]);
});

test('filters by evidence, module, date range, validation status, and timestamp certainty', () => {
  const events = createTimelineEvents(caseId, [fixture], { [fixture.id]: { custody: true } });
  expect(filterTimelineEvents(events, { evidenceId: fixture.id, module: 'SQLite' }).every((event) => event.sourceModule === 'SQLite')).toBe(true);
  expect(filterTimelineEvents(events, { startDate: '2026-10-30', endDate: '2026-10-30', timestampStatus: 'known' })
    .every((event) => event.timestamp?.startsWith('2026-10-30'))).toBe(true);
  expect(filterTimelineEvents(events, { validationStatus: 'VERIFIED' }).every((event) => event.validationStatus === 'VERIFIED')).toBe(true);
  expect(filterTimelineEvents(events, { timestampStatus: 'unknown' }).every((event) => !event.timestamp)).toBe(true);
});

test('creates a comprehensive report separating verified findings, leads, and unsupported claims', () => {
  const events = createTimelineEvents(caseId, [fixture], { [fixture.id]: { custody: true, sha256: 'SHA-256 verified' } });
  const before = JSON.stringify(fixture);
  const report = createInvestigationReport({
    caseId,
    records: [fixture],
    timelineEvents: events,
    integrity: { [fixture.id]: { sha256: 'SHA-256 verified', custody: 'VERIFIED' } },
    summary: 'Synthetic investigation summary.',
    conclusions: 'Conclusions require independent review.',
    generatedAt: '2026-10-30T17:00:00.000Z',
  });
  expect(report.case).toMatchObject({ caseId, investigationSummary: 'Synthetic investigation summary.' });
  expect(report.evidenceInventory[0]).toMatchObject({
    evidenceId: fixture.id,
    sha256: fixture.sha256,
    integrityStatus: 'SHA-256 verified',
    custodyStatus: 'VERIFIED',
  });
  expect(report.forensicFindings[0]).toHaveProperty('windowsRegistry');
  expect(report.forensicFindings[0]).toHaveProperty('pcap');
  expect(report.forensicFindings[0]).toHaveProperty('sqlite');
  expect(report.aiAssistedInterpretations[0].observedEvidence).toEqual(fixture.copilotFindings[0].observedEvidence);
  expect(report.classifications.verifiedFindings).toEqual([]);
  expect(report.classifications.unverifiedLeads.length).toBeGreaterThan(0);
  expect(report.classifications.unsupportedClaims[0]).toMatchObject(fixture.copilotFindings[0].unsupportedClaims[0]);
  expect(report.humanValidationResults.some((item) => item.investigatorId === undefined && item.status === 'VERIFIED')).toBe(true);
  expect(report.timeline).toEqual(events);
  expect(report.limitations.some((item) => item.includes('TIME ZONE UNKNOWN'))).toBe(true);
  expect(JSON.stringify(fixture)).toBe(before);
});

test('only classifies AI interpretations as verified after an authorized independent human review', () => {
  const record = {
    ...fixture,
    copilotFindings: [{
      ...fixture.copilotFindings[0],
      validationStatus: 'VERIFIED',
      validationHistory: [{
        status: 'VERIFIED',
        investigatorId: 'authenticated-investigator-id',
        independentMethod: 'Independent offline comparison',
        notes: 'Compared against independent synthetic evidence.',
      }],
    }],
  };
  const events = createTimelineEvents(caseId, [record]);
  const report = createInvestigationReport({ caseId, records: [record], timelineEvents: events });
  expect(report.classifications.verifiedFindings).toHaveLength(1);
  expect(report.classifications.verifiedFindings[0].validatedBy).toBe('authenticated-investigator-id');
  expect(report.classifications.unverifiedLeads.some((claim) => claim.text === record.copilotFindings[0].investigativeLeads[0].text)).toBe(true);

  const missingIndependentMethod = {
    ...record,
    copilotFindings: [{
      ...record.copilotFindings[0],
      validationHistory: [{ status: 'VERIFIED', investigatorId: 'authenticated-investigator-id' }],
    }],
  };
  const unverifiedReport = createInvestigationReport({
    caseId,
    records: [missingIndependentMethod],
    timelineEvents: createTimelineEvents(caseId, [missingIndependentMethod]),
  });
  expect(unverifiedReport.classifications.verifiedFindings).toEqual([]);
});

test('exports timeline CSV with all required fields and safe escaping', () => {
  const events = createTimelineEvents(caseId, [{
    ...fixture,
    exif: { capturedAt: '2026:10:30 10:11:12' },
    registryAnalysis: { report: { artifacts: [{ type: 'Example, "quoted"', keyPath: 'Software\\Example', values: [] }] } },
    pcapAnalysis: null,
    sqliteAnalysis: null,
    custody: [],
    copilotFindings: [],
  }]);
  const csv = timelineToCsv(events.filter((event) => event.artifactReference === 'EXIF DateTimeOriginal'));
  expect(csv.split('\r\n')[0]).toContain('originalTimestamp,timeZone,timestampStatus,sourceModule,caseId,evidenceId');
  expect(csv).toContain('"SYNTHETIC-CASE"');
  expect(csv).toContain('AMBIGUOUS — TIME ZONE UNKNOWN');
  expect(timelineToCsv([]).split('\r\n')).toHaveLength(1);
});

test('handles missing and malformed module metadata without inventing timestamps', () => {
  const events = createTimelineEvents(caseId, [{
    id: 'malformed-record',
    caseId,
    custody: [null, { action: 'Received', timestamp: 'not-a-date' }],
    exif: { capturedAt: '' },
    registryAnalysis: { report: { artifacts: [null, { type: 'Artifact', values: null }] } },
    pcapAnalysis: { report: { packets: [null], connections: [null], leads: [null] } },
    sqliteAnalysis: { report: { tables: [null, { name: 'empty', timestampFields: [null, { column: 'created_at', examples: [null, {}] }] }] } },
    copilotFindings: [null],
  }]);
  expect(events.length).toBeGreaterThan(0);
  expect(events.every((event) => event.timestamp === null || Number.isFinite(Date.parse(event.timestamp)))).toBe(true);
  expect(events.find((event) => event.sourceModule === 'Chain of custody' && event.description.startsWith('Received'))?.timestampStatus).toBe('UNRECOGNIZED');
});
