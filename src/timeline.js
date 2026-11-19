const VALIDATION_STATUSES = new Set(['VERIFIED', 'MISMATCH', 'NEEDS REVIEW']);
const DATE_ONLY = /^(\d{4})[-:](\d{2})[-:](\d{2})$/;
const EXIF_DATE = /^(\d{4}):(\d{2}):(\d{2})[ T](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?$/;
const ISO_DATE_TIME = /^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:?\d{2})$/i;
const LOCAL_DATE_TIME = /^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2})(?::(\d{2})(?:\.(\d+))?)?$/;

function validDateParts(year, month, day, hour = 0, minute = 0, second = 0) {
  const date = new Date(Date.UTC(year, month - 1, day, hour, minute, second));
  return date.getUTCFullYear() === year
    && date.getUTCMonth() === month - 1
    && date.getUTCDate() === day
    && date.getUTCHours() === hour
    && date.getUTCMinutes() === minute
    && date.getUTCSeconds() === second;
}

function utcIso(year, month, day, hour, minute, second, milliseconds, offsetMinutes = 0) {
  const date = new Date(Date.UTC(year, month - 1, day, hour, minute, second, milliseconds) - offsetMinutes * 60_000);
  return Number.isNaN(date.getTime()) ? null : date.toISOString();
}

function parseOffset(value) {
  if (value.toUpperCase() === 'Z') return { minutes: 0, label: 'UTC (Z)' };
  const match = /^([+-])(\d{2}):?(\d{2})$/.exec(value);
  if (!match) return null;
  const hours = Number(match[2]);
  const minutes = Number(match[3]);
  if (hours > 14 || minutes > 59 || hours === 14 && minutes !== 0) return null;
  const sign = match[1] === '+' ? 1 : -1;
  return {
    minutes: sign * (hours * 60 + minutes),
    label: `UTC${match[1]}${match[2]}:${match[3]}`,
  };
}

export function normalizeTimelineTimestamp(value, options = {}) {
  const { allowUnixEpoch = false } = options;
  const originalTimestamp = Object.hasOwn(options, 'originalTimestamp')
    ? options.originalTimestamp
    : value === null || value === undefined ? null : value;
  if (typeof value === 'number' && allowUnixEpoch && Number.isFinite(value)) {
    const milliseconds = Math.abs(value) >= 1e12 && Math.abs(value) < 1e14
      ? value
      : Math.abs(value) >= 1e9 && Math.abs(value) < 1e11
        ? value * 1000
        : null;
    if (milliseconds !== null) {
      const date = new Date(milliseconds);
      if (!Number.isNaN(date.getTime())) {
        return { normalizedTimestamp: date.toISOString(), originalTimestamp, timeZone: 'UTC (Unix epoch)', timestampStatus: 'NORMALIZED UTC' };
      }
    }
    return { normalizedTimestamp: null, originalTimestamp, timeZone: 'Unknown', timestampStatus: 'AMBIGUOUS' };
  }
  if (typeof value !== 'string' || !value.trim()) {
    return {
      normalizedTimestamp: null,
      originalTimestamp,
      timeZone: 'Unknown',
      timestampStatus: value === null || value === undefined ? 'UNKNOWN TIME' : 'INVALID',
    };
  }
  const source = value.trim();
  const dateOnly = DATE_ONLY.exec(source);
  if (dateOnly) {
    const [, yearText, monthText, dayText] = dateOnly;
    if (!validDateParts(Number(yearText), Number(monthText), Number(dayText))) {
      return { normalizedTimestamp: null, originalTimestamp, timeZone: 'Unknown', timestampStatus: 'INVALID' };
    }
    return {
      normalizedTimestamp: null,
      originalTimestamp,
      timeZone: 'Unknown',
      timestampStatus: 'AMBIGUOUS DATE — TIME NOT PROVIDED',
    };
  }

  const exif = EXIF_DATE.exec(source);
  const iso = ISO_DATE_TIME.exec(source);
  const local = LOCAL_DATE_TIME.exec(source);
  const match = exif || iso || local;
  if (!match) {
    return {
      normalizedTimestamp: null,
      originalTimestamp,
      timeZone: 'Unknown',
      timestampStatus: /^[+-]?\d{8,}$/.test(source) ? 'AMBIGUOUS' : 'UNRECOGNIZED',
    };
  }
  const [, yearText, monthText, dayText, hourText, minuteText, secondText = '0', fraction = '', offsetValue] = match;
  const [year, month, day, hour, minute, second] = [yearText, monthText, dayText, hourText, minuteText, secondText].map(Number);
  if (!validDateParts(year, month, day, hour, minute, second) || hour > 23 || minute > 59 || second > 59) {
    return { normalizedTimestamp: null, originalTimestamp, timeZone: 'Unknown', timestampStatus: 'INVALID' };
  }
  if (exif || local) {
    return {
      normalizedTimestamp: null,
      originalTimestamp,
      timeZone: 'Unknown (source did not provide an offset)',
      timestampStatus: 'AMBIGUOUS — TIME ZONE UNKNOWN',
    };
  }
  const offset = parseOffset(offsetValue);
  if (!offset) return { normalizedTimestamp: null, originalTimestamp, timeZone: 'Unknown', timestampStatus: 'INVALID OFFSET' };
  const milliseconds = Number(`0.${fraction || '0'}`) * 1000;
  const normalizedTimestamp = utcIso(year, month, day, hour, minute, second, milliseconds, offset.minutes);
  return {
    normalizedTimestamp,
    originalTimestamp,
    timeZone: offset.label,
    timestampStatus: normalizedTimestamp ? 'NORMALIZED UTC' : 'INVALID',
  };
}

function validationStatus(value) {
  return VALIDATION_STATUSES.has(value) ? value : 'NEEDS REVIEW';
}

function isAuthorizedCopilotValidation(validation) {
  return validation?.status === 'VERIFIED'
    && typeof validation.investigatorId === 'string'
    && Boolean(validation.investigatorId.trim())
    && typeof validation.independentMethod === 'string'
    && Boolean(validation.independentMethod.trim())
    && typeof validation.notes === 'string'
    && Boolean(validation.notes.trim());
}

function createEvent(caseId, record, module, artifactReference, description, rawTimestamp, status = 'NEEDS REVIEW', options = {}) {
  const time = normalizeTimelineTimestamp(rawTimestamp, options);
  return {
    id: `${record.id}:${module}:${artifactReference}:${String(rawTimestamp ?? 'unknown')}:${description}`.slice(0, 1_000),
    timestamp: time.normalizedTimestamp,
    originalTimestamp: time.originalTimestamp,
    timeZone: time.timeZone,
    timestampStatus: time.timestampStatus,
    sourceModule: module,
    caseId,
    evidenceId: record.id,
    filename: record.name || 'Unknown filename',
    artifactReference: String(artifactReference || 'Unspecified artifact').slice(0, 500),
    description: String(description || 'Forensic artifact').slice(0, 1_000),
    validationStatus: validationStatus(status),
    classification: status === 'VERIFIED' ? 'VERIFIED FINDING' : 'UNVERIFIED / NEEDS REVIEW',
  };
}

function exifEvents(caseId, record) {
  const fields = [
    ['capturedAt', 'EXIF DateTimeOriginal'],
    ['digitizedAt', 'EXIF DateTimeDigitized'],
    ['modifiedAt', 'EXIF DateTime'],
  ];
  return fields.flatMap(([field, artifact]) => {
    const value = record.exif?.[field];
    if (value === undefined || value === null || value === '') return [];
    return [createEvent(
      caseId,
      record,
      'EXIF',
      artifact,
      `${artifact}: ${String(value)}`,
      value,
      record.exifValidation?.status,
    )];
  });
}

function registryEvents(caseId, record) {
  const artifacts = record.registryAnalysis?.report?.artifacts;
  if (!Array.isArray(artifacts)) return [];
  return artifacts.flatMap((artifact) => {
    if (!artifact || typeof artifact !== 'object') return [];
    const artifactRef = artifact?.keyPath || 'Registry artifact path unavailable';
    const values = Array.isArray(artifact?.values) ? artifact.values : [];
    const timestampValues = values.filter((item) => /(time|date|created|modified|installed|lastwrite|lastseen)/i.test(String(item?.name || '')));
    const recognized = timestampValues.length
      ? timestampValues
      : [{ name: 'timestamp not identified', data: null }];
    return recognized.map((item) => createEvent(
      caseId,
      record,
      'Windows Registry',
      `${artifactRef} / ${item.name || 'unnamed value'}`,
      `${artifact?.type || 'Registry artifact'}${item.data === null || item.data === undefined ? ' (no explicit timestamp value)' : ` — ${item.name}: ${String(item.data)}`}`,
      item.data,
      record.registryAnalysis?.status,
    ));
  });
}

function pcapEvents(caseId, record) {
  const report = record.pcapAnalysis?.report;
  if (!report) return [];
  const status = record.pcapAnalysis.status || 'NEEDS REVIEW';
  const events = (Array.isArray(report.packets) ? report.packets : []).flatMap((packet, index) => {
    if (!packet || typeof packet !== 'object') return [];
    return [createEvent(
      caseId,
      record,
      'PCAP',
      `Packet ${index + 1}`,
      `${packet.protocol || 'Unknown protocol'}: ${packet.sourceIp || '?'}:${packet.sourcePort ?? '?'} → ${packet.destinationIp || '?'}:${packet.destinationPort ?? '?'} (${packet.bytes ?? 'unknown'} bytes)`,
      packet.timestamp,
      status,
      { originalTimestamp: packet.originalTimestamp ?? packet.timestamp },
    )];
  });
  for (const [index, connection] of (Array.isArray(report.connections) ? report.connections : []).entries()) {
    if (!connection || typeof connection !== 'object') continue;
    const reference = `Connection ${index + 1}: ${connection.endpointA || '?'} ↔ ${connection.endpointB || '?'}`;
    events.push(createEvent(
      caseId,
      record,
      'PCAP',
      reference,
      `${connection.protocol || 'Unknown protocol'} connection summary: ${connection.packets ?? 'unknown'} packets, ${connection.bytes ?? 'unknown'} bytes`,
      connection.firstSeen,
      status,
      { originalTimestamp: connection.originalFirstSeen ?? connection.firstSeen },
    ));
    if (connection.lastSeen && connection.lastSeen !== connection.firstSeen) {
      events.push(createEvent(
        caseId,
        record,
        'PCAP',
        reference,
        'Connection last observed',
        connection.lastSeen,
        status,
        { originalTimestamp: connection.originalLastSeen ?? connection.lastSeen },
      ));
    }
  }
  (Array.isArray(report.leads) ? report.leads : []).forEach((lead, index) => {
    if (!lead || typeof lead !== 'object') return;
    events.push(createEvent(
      caseId,
      record,
      'PCAP',
      `Network lead ${index + 1}`,
      `${lead.indicator || 'Network lead'} — ${lead.note || lead.classification || 'Requires analyst review; not a confirmed threat.'}`,
      null,
      'NEEDS REVIEW',
    ));
  });
  return events;
}

function sqliteEvents(caseId, record) {
  const tables = record.sqliteAnalysis?.report?.tables;
  if (!Array.isArray(tables)) return [];
  const events = [];
  for (const table of tables) {
    if (!table || typeof table !== 'object') continue;
    for (const field of Array.isArray(table?.timestampFields) ? table.timestampFields : []) {
      if (!field || typeof field !== 'object') continue;
      const examples = Array.isArray(field.examples) ? field.examples : [];
      if (!examples.length) {
        events.push(createEvent(
          caseId,
          record,
          'SQLite',
          `${table.name || 'table'}.${field.column || 'timestamp'}`,
          `Timestamp-like field identified but no timestamp values were recognized`,
          null,
          record.sqliteAnalysis?.status,
        ));
      }
      for (const example of examples) {
        if (!example || typeof example !== 'object') continue;
        const unixEpochString = typeof example.raw === 'string'
          && /^Unix (seconds|milliseconds)$/.test(example.reason || '')
          && /^-?\d{10,13}$/.test(example.raw.trim());
        const timestampValue = unixEpochString ? Number(example.raw) : example.raw;
        events.push(createEvent(
          caseId,
          record,
          'SQLite',
          `${table.name || 'table'}.${field.column || 'timestamp'}`,
          `Database timestamp value (${example.reason || 'parser-recognized value'}): ${String(example.raw)}`,
          timestampValue,
          record.sqliteAnalysis?.status,
          {
            allowUnixEpoch: typeof example.raw === 'number' || unixEpochString,
            ...(unixEpochString ? { originalTimestamp: example.raw } : {}),
          },
        ));
      }
    }
  }
  return events;
}

function custodyEvents(caseId, record, integrity) {
  return (Array.isArray(record.custody) ? record.custody : []).map((entry, index) => createEvent(
    caseId,
    record,
    'Chain of custody',
    `Custody event ${index + 1}${entry?.eventHash ? ` / ${entry.eventHash}` : ''}`,
    `${entry?.action || 'Custody action not specified'} by ${entry?.actor || 'actor not specified'}${entry?.previousHash ? `; previous event hash ${entry.previousHash}` : ''}`,
    entry?.timestamp,
    integrity?.[record.id]?.custody === true ? 'VERIFIED' : 'NEEDS REVIEW',
  ));
}

function validationEvents(caseId, record) {
  const events = [];
  const validations = [
    ['EXIF validation', record.exifValidation],
    ['Windows Registry validation', record.registryAnalysis],
    ['PCAP validation', record.pcapAnalysis],
    ['SQLite validation', record.sqliteAnalysis],
  ];
  for (const [module, validation] of validations) {
    if (validation?.reviewedAt) {
      events.push(createEvent(
        caseId,
        record,
        module,
        (Array.isArray(validation.artifactReferences) ? validation.artifactReferences : []).join(', ') || 'Analyst validation',
        `Human validation recorded by ${validation.analyst || 'analyst not specified'}${validation.notes ? `: ${validation.notes}` : ''}`,
        validation.reviewedAt,
        validation.status,
      ));
    }
  }
  return events;
}

function copilotEvents(caseId, record) {
  const events = [];
  for (const finding of Array.isArray(record.copilotFindings) ? record.copilotFindings : []) {
    if (!finding || typeof finding !== 'object') continue;
    const refs = (Array.isArray(finding.observedEvidence) ? finding.observedEvidence : [])
      .map((fact) => `${fact.evidenceId || record.id}:${fact.artifactReference || fact.referenceId || 'artifact'}`);
    const reference = refs.join('; ') || record.id;
    events.push(createEvent(
      caseId,
      record,
      'AI Forensic Copilot',
      reference,
      `AI-assisted interpretation created: ${finding.question || 'Question unavailable'}; ${finding.interpretations?.length || 0} interpretations, ${finding.investigativeLeads?.length || 0} leads`,
      finding.createdAt,
      'NEEDS REVIEW',
    ));
      for (const validation of Array.isArray(finding.validationHistory) ? finding.validationHistory : []) {
        if (!validation || typeof validation !== 'object') continue;
      events.push(createEvent(
        caseId,
        record,
        'Human validation',
        reference,
        `${isAuthorizedCopilotValidation(validation) ? 'Authorized human validation' : 'Validation submitted'} (${validation.status || 'NEEDS REVIEW'}) by ${validation.analyst || 'investigator not specified'}${validation.independentMethod ? ` using ${validation.independentMethod}` : ''}`,
        validation.reviewedAt,
        isAuthorizedCopilotValidation(validation) ? validation.status : 'NEEDS REVIEW',
      ));
    }
  }
  return events;
}

function compareEvents(left, right) {
  if (left.timestamp && right.timestamp) return left.timestamp.localeCompare(right.timestamp) || left.id.localeCompare(right.id);
  if (left.timestamp) return -1;
  if (right.timestamp) return 1;
  return left.sourceModule.localeCompare(right.sourceModule) || left.id.localeCompare(right.id);
}

export function createTimelineEvents(caseId, records, integrity = {}) {
  if (typeof caseId !== 'string' || !caseId.trim()) throw new Error('A case ID is required to build the timeline.');
  if (!Array.isArray(records)) throw new TypeError('Timeline records must be an array.');
  const events = records.flatMap((record) => {
    if (!record || record.caseId !== caseId) return [];
    return [
      ...exifEvents(caseId, record),
      ...registryEvents(caseId, record),
      ...pcapEvents(caseId, record),
      ...sqliteEvents(caseId, record),
      ...custodyEvents(caseId, record, integrity),
      ...validationEvents(caseId, record),
      ...copilotEvents(caseId, record),
    ];
  });
  return events.sort(compareEvents);
}

export function filterTimelineEvents(events, filters = {}) {
  const {
    evidenceId = '',
    module = '',
    startDate = '',
    endDate = '',
    validationStatus = '',
    timestampStatus = '',
  } = filters;
  return events.filter((event) => {
    if (evidenceId && event.evidenceId !== evidenceId) return false;
    if (module && event.sourceModule !== module) return false;
    if (validationStatus && event.validationStatus !== validationStatus) return false;
    if (timestampStatus === 'known' && !event.timestamp) return false;
    if (timestampStatus === 'unknown' && event.timestamp) return false;
    if (startDate && (!event.timestamp || event.timestamp.slice(0, 10) < startDate)) return false;
    if (endDate && (!event.timestamp || event.timestamp.slice(0, 10) > endDate)) return false;
    return true;
  });
}

export function createInvestigationReport({ caseId, records, timelineEvents, integrity = {}, summary = '', conclusions = '', generatedAt = new Date().toISOString() }) {
  if (typeof caseId !== 'string' || !caseId.trim() || !Array.isArray(records) || !Array.isArray(timelineEvents)) {
    throw new Error('Case, evidence records, and timeline events are required for an investigation report.');
  }
  const caseRecords = records.filter((record) => record?.caseId === caseId);
  const findings = caseRecords.flatMap((record) => (Array.isArray(record.copilotFindings) ? record.copilotFindings : [])
    .filter((finding) => finding && typeof finding === 'object')
    .map((finding) => ({
      ...finding,
      savedOnEvidenceId: record.id,
      filename: record.name || 'Unknown filename',
    })));
  const hasAuthorizedHumanVerification = (finding) => finding.validationStatus === 'VERIFIED'
    && Array.isArray(finding.validationHistory)
    && isAuthorizedCopilotValidation(finding.validationHistory.at(-1));
  const humanValidations = [
    ...caseRecords.flatMap((record) => [
      ...(record.exifValidation ? [{ evidenceId: record.id, module: 'EXIF', ...record.exifValidation }] : []),
      ...['registryAnalysis', 'pcapAnalysis', 'sqliteAnalysis'].flatMap((key) => (
        record[key] ? [{ evidenceId: record.id, module: key, ...record[key] }] : []
      )),
      ...(Array.isArray(record.copilotFindings) ? record.copilotFindings : [])
        .filter((finding) => finding && typeof finding === 'object')
        .flatMap((finding) => (
        (Array.isArray(finding.validationHistory) ? finding.validationHistory : []).map((validation) => ({
          evidenceId: record.id,
          findingId: finding.id,
          ...validation,
          submittedStatus: validation?.status || 'NEEDS REVIEW',
          status: isAuthorizedCopilotValidation(validation) ? validation.status : 'NEEDS REVIEW',
          authorizationStatus: isAuthorizedCopilotValidation(validation) ? 'AUTHORIZED INVESTIGATOR' : 'NOT VERIFIED',
        }))
      )),
    ]),
  ];
  const classifications = {
    verifiedFindings: findings.flatMap((finding) => (hasAuthorizedHumanVerification(finding)
      ? (Array.isArray(finding.interpretations) ? finding.interpretations : []).map((claim) => ({
        ...claim,
        findingId: finding.id,
        question: finding.question,
        evidenceId: finding.savedOnEvidenceId,
        validatedBy: finding.validationHistory.at(-1)?.investigatorId,
      }))
      : [])),
    unverifiedLeads: [
      ...findings.flatMap((finding) => [
        ...(hasAuthorizedHumanVerification(finding) ? [] : (Array.isArray(finding.interpretations) ? finding.interpretations : []).map((claim) => ({
          ...claim,
          findingId: finding.id,
          question: finding.question,
          evidenceId: finding.savedOnEvidenceId,
        }))),
        ...(Array.isArray(finding.investigativeLeads) ? finding.investigativeLeads : []).map((claim) => ({
          ...claim,
          findingId: finding.id,
          question: finding.question,
          evidenceId: finding.savedOnEvidenceId,
        })),
      ]),
      ...caseRecords.flatMap((record) => (Array.isArray(record.pcapAnalysis?.report?.leads) ? record.pcapAnalysis.report.leads : [])
        .map((lead) => ({ evidenceId: record.id, module: 'PCAP', ...lead }))),
    ],
    unsupportedClaims: findings.flatMap((finding) => (Array.isArray(finding.unsupportedClaims) ? finding.unsupportedClaims : [])
      .map((claim) => ({ ...claim, findingId: finding.id, evidenceId: finding.savedOnEvidenceId }))),
  };
  const unresolvedQuestions = findings
    .filter((finding) => !hasAuthorizedHumanVerification(finding))
    .map((finding) => finding.question)
    .filter(Boolean);
  const caseTimeline = timelineEvents.filter((event) => event?.caseId === caseId);
  const unknownTimestampEvents = caseTimeline.filter((event) => !event.timestamp);
  const timeLimitations = unknownTimestampEvents.map((event) => ({
    evidenceId: event.evidenceId,
    module: event.sourceModule,
    artifactReference: event.artifactReference,
    originalTimestamp: event.originalTimestamp,
    timestampStatus: event.timestampStatus,
    timeZone: event.timeZone,
  }));
  return {
    format: 'ForensiAI Investigation Report',
    version: 1,
    generatedAt,
    case: { caseId, investigationSummary: summary.trim(), investigatorConclusions: conclusions.trim() },
    evidenceInventory: caseRecords.map((record) => ({
      caseId,
      evidenceId: record.id,
      filename: record.name || 'Unknown filename',
      type: record.type || 'Unknown',
      size: Number.isFinite(record.size) ? record.size : null,
      addedAt: record.createdAt || null,
      sha256: record.sha256 || null,
      integrityStatus: integrity[record.id]?.sha256 || 'NOT RECHECKED',
      custodyStatus: integrity[record.id]?.custody || 'NOT RECHECKED',
      custodyHistory: Array.isArray(record.custody) ? record.custody : [],
    })),
    forensicFindings: caseRecords.map((record) => ({
      evidenceId: record.id,
      filename: record.name || 'Unknown filename',
      exif: record.exif ? { metadata: record.exif, validation: record.exifValidation || null } : null,
      windowsRegistry: record.registryAnalysis || null,
      pcap: record.pcapAnalysis || null,
      sqlite: record.sqliteAnalysis || null,
    })),
    aiAssistedInterpretations: findings,
    humanValidationResults: humanValidations,
    classifications,
    timeline: caseTimeline,
    limitations: [
      'Timeline events without a normalized timestamp are listed separately with the original value and timestamp ambiguity preserved.',
      'EXIF local timestamps without an offset are not converted to UTC.',
      ...timeLimitations.map((item) => `${item.module} ${item.evidenceId} ${item.artifactReference}: ${item.timestampStatus}; time zone ${item.timeZone}; original value ${String(item.originalTimestamp ?? 'not provided')}.`),
      ...caseRecords.flatMap((record) => (Array.isArray(record.pcapAnalysis?.report?.warnings) ? record.pcapAnalysis.report.warnings : []).map((warning) => `PCAP ${record.id}: ${warning}`)),
      ...caseRecords.flatMap((record) => (Array.isArray(record.registryAnalysis?.report?.warnings) ? record.registryAnalysis.report.warnings : []).map((warning) => `Registry ${record.id}: ${warning}`)),
      ...caseRecords.flatMap((record) => (Array.isArray(record.sqliteAnalysis?.report?.warnings) ? record.sqliteAnalysis.report.warnings : []).map((warning) => `SQLite ${record.id}: ${warning}`)),
      ...caseRecords.flatMap((record) => (Array.isArray(record.pcapAnalysis?.report?.leads) ? record.pcapAnalysis.report.leads : [])
        .filter((lead) => lead && typeof lead === 'object')
        .map((lead) => `PCAP lead for ${record.id} is heuristic and is not a confirmed threat: ${lead.indicator || 'Unspecified lead'}.`)),
      ...caseRecords.filter((record) => integrity[record.id]?.sha256 && integrity[record.id].sha256 !== 'SHA-256 verified')
        .map((record) => `Evidence ${record.id} integrity check: ${integrity[record.id].sha256}.`),
      ...caseRecords.filter((record) => integrity[record.id]?.custody && integrity[record.id].custody !== 'VERIFIED')
        .map((record) => `Evidence ${record.id} custody-chain check: ${integrity[record.id].custody}.`),
    ],
    unresolvedInvestigativeQuestions: [...new Set(unresolvedQuestions)],
  };
}

const csvColumns = [
  'timestamp',
  'originalTimestamp',
  'timeZone',
  'timestampStatus',
  'sourceModule',
  'caseId',
  'evidenceId',
  'filename',
  'artifactReference',
  'description',
  'validationStatus',
  'classification',
];

function csvEscape(value) {
  const text = value === null || value === undefined ? '' : typeof value === 'object' ? JSON.stringify(value) : String(value);
  return `"${text.replaceAll('"', '""')}"`;
}

export function timelineToCsv(events) {
  if (!Array.isArray(events)) throw new TypeError('Timeline events must be an array.');
  return [
    csvColumns.join(','),
    ...events.map((event) => csvColumns.map((column) => csvEscape(event[column])).join(',')),
  ].join('\r\n');
}
