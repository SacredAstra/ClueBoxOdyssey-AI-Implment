export const COPILOT_UNAVAILABLE_MESSAGE = 'AI Copilot unavailable — secure AI provider configuration required.';
export const COPILOT_VALIDATION_STATUSES = ['VERIFIED', 'MISMATCH', 'NEEDS REVIEW'];
const MAX_QUESTION_LENGTH = 2_000;
const MAX_FACTS = 100;
const MAX_VALUE_LENGTH = 500;
export const MAX_COPILOT_REQUEST_BYTES = 20_000;
const MAX_RESPONSE_BYTES = 64_000;
const REQUEST_TIMEOUT_MS = 25_000;

const moduleFields = [
  ['exif', 'EXIF', (data) => Object.entries(data).map(([field, value]) => ({ type: 'EXIF field', reference: field, value }))],
  ['registryAnalysis', 'Windows Registry', (data) => (data.report?.artifacts || []).map((item) => ({
    type: item.type,
    reference: item.keyPath,
    value: item.values.map((entry) => `${entry.name}=${typeof entry.data === 'object' ? JSON.stringify(entry.data) : String(entry.data)}`).join('; ').slice(0, MAX_VALUE_LENGTH),
  }))],
  ['pcapAnalysis', 'PCAP', (data) => [
    ...(data.report?.connections || []).map((connection) => ({
      type: 'Connection summary',
      reference: `${connection.protocol} ${connection.endpointA} ↔ ${connection.endpointB}`,
      value: `${connection.packets} packets, ${connection.bytes} bytes; ${connection.firstSeen || 'timestamp unavailable'} to ${connection.lastSeen || 'timestamp unavailable'}`,
    })),
    ...(data.report?.packets || []).slice(0, 20).map((packet) => ({
      type: 'Packet summary',
      reference: `${packet.timestamp || 'timestamp unavailable'} ${packet.protocol || 'unknown protocol'}`,
      value: `${packet.sourceIp || 'unknown source'}:${packet.sourcePort ?? '?'} → ${packet.destinationIp || 'unknown destination'}:${packet.destinationPort ?? '?'}`,
    })),
    ...(data.report?.leads || []).map((lead) => ({
      type: lead.indicator || 'Network lead',
      reference: `${lead.sourceIp || 'unknown source'} → ${lead.destinationIp || 'unknown destination'}`,
      value: lead.note || lead.classification || 'Lead requires analyst review.',
      validationStatus: 'NEEDS REVIEW',
    })),
  ]],
  ['sqliteAnalysis', 'SQLite', (data) => (data.report?.tables || []).flatMap((table) => [
    {
      type: 'Database schema',
      reference: `${table.type} ${table.name}`,
      value: (table.columns || []).map((column) => `${column.name} ${column.type}${column.primaryKey ? ' PRIMARY KEY' : ''}`).join(', ').slice(0, MAX_VALUE_LENGTH),
    },
    ...(table.records || []).slice(0, 5).map((record, index) => ({
      type: 'Database record',
      reference: `${table.name} row ${index + 1}`,
      value: JSON.stringify(record),
    })),
    ...(table.timestampFields || []).flatMap((field) => field.examples.map((example) => ({
      type: 'Timestamp field',
      reference: `${table.name}.${field.column}`,
      value: `${JSON.stringify(example.raw)} → ${example.iso} (${example.reason})`,
    }))),
  ])],
];

function boundedText(value, maxLength = MAX_VALUE_LENGTH) {
  if (typeof value === 'string') return value.slice(0, maxLength);
  if (value === null || value === undefined) return '';
  return String(value).slice(0, maxLength);
}

export async function buildCopilotEvidenceContext(caseId, records, verifyEvidence, verifyCustodyChain) {
  if (typeof caseId !== 'string' || !caseId.trim()) throw new Error('Select an investigation case.');
  if (!Array.isArray(records) || !records.length) throw new Error('Select at least one evidence record.');
  if (records.length > 10) throw new Error('Select no more than 10 evidence records for one question.');
  if (typeof verifyEvidence !== 'function') throw new Error('Evidence integrity verification is unavailable.');
  if (typeof verifyCustodyChain !== 'function') throw new Error('Custody-chain verification is unavailable.');

  const facts = [];
  const perRecordLimit = Math.floor(MAX_FACTS / records.length);
  for (const record of records) {
    if (record.caseId !== caseId.trim()) throw new Error('Selected evidence does not belong to the active case.');
    const integrityStatus = await verifyEvidence(record);
    const custodyValid = await verifyCustodyChain(record.custody);
    const evidenceIntegrity = integrityStatus === true ? 'SHA-256 verified' : 'SHA-256 verification failed';
    const custodyStatus = custodyValid === true ? 'custody chain verified' : 'custody chain not verified';
    const base = {
      caseId: caseId.trim(),
      evidenceId: boundedText(record.id, 128),
      filename: boundedText(record.name, 240),
      sha256: boundedText(record.sha256, 64),
      integrityStatus: evidenceIntegrity,
      custodyStatus,
      validationStatus: 'NEEDS REVIEW',
    };
    let recordFactCount = 0;
    let omittedFactCount = 0;
    const addFact = (module, type, reference, value, validationStatus = 'NEEDS REVIEW') => {
      if (value === '' || value === null || value === undefined) return;
      if (facts.length >= MAX_FACTS || recordFactCount >= perRecordLimit - 1) {
        omittedFactCount += 1;
        return;
      }
      facts.push({
        referenceId: `E${facts.length + 1}`,
        ...base,
        module,
        artifactType: boundedText(type, 120),
        artifactReference: boundedText(reference, 500),
        value: boundedText(value),
        validationStatus,
      });
      recordFactCount += 1;
    };

    addFact('Evidence inventory', 'Evidence record', record.id, `${record.type || 'Unknown type'}; ${record.size} bytes; SHA-256 ${record.sha256}`);
    for (const [field, module, extract] of moduleFields) {
      const analysis = record[field];
      if (!analysis) continue;
      if (field !== 'exif' && analysis.sourceSha256 !== record.sha256) {
        const status = analysis.sourceSha256 ? 'MISMATCH' : 'NEEDS REVIEW';
        const detail = analysis.sourceSha256
          ? 'The saved analysis source hash differs from the current evidence hash; report artifacts are omitted.'
          : 'The saved analysis has no source hash binding; report artifacts are omitted.';
        addFact(module, 'Analysis provenance warning', 'source SHA-256', detail, status);
        continue;
      }
      const validationStatus = analysis.status || analysis.validation?.status || 'NEEDS REVIEW';
      for (const item of extract(analysis)) {
        addFact(module, item.type, item.reference, item.value, item.validationStatus || validationStatus);
      }
      if (analysis.status || analysis.notes || analysis.artifactReferences?.length) {
        addFact(
          module,
          'Analyst validation',
          'Saved analyst review',
          `${analysis.status || 'NEEDS REVIEW'} by ${analysis.analyst || 'analyst not recorded'}; notes: ${analysis.notes || 'none'}; artifact references: ${(analysis.artifactReferences || []).join(', ') || 'none'}`,
          validationStatus,
        );
      }
    }

    const exifValidation = record.exifValidation;
    if (exifValidation) {
      addFact('Manual EXIF validation', 'Analyst assessment', record.id, `${exifValidation.status}: ${exifValidation.notes || 'No notes supplied.'}`, exifValidation.status);
    }
    const custody = Array.isArray(record.custody) ? record.custody : [];
    addFact('Chain of custody', 'Custody summary', record.id, `${custody.length} custody events; ${custody.at(-1)?.action || 'No custody actions'}`, custodyStatus === 'custody chain verified' ? 'VERIFIED' : 'NEEDS REVIEW');
    for (const event of custody.slice(-5)) {
      addFact(
        'Chain of custody',
        'Custody event',
        `${event.timestamp} / ${event.eventHash}`,
        `${event.action} by ${event.actor}; previous event hash ${event.previousHash}`,
        custodyStatus === 'custody chain verified' ? 'VERIFIED' : 'NEEDS REVIEW',
      );
    }
    if (omittedFactCount && facts.length < MAX_FACTS) {
      facts.push({
        referenceId: `E${facts.length + 1}`,
        ...base,
        module: 'Copilot context',
        artifactType: 'Context limit',
        artifactReference: record.id,
        value: `${omittedFactCount} additional structured facts from this evidence record were omitted due to context limits.`,
        validationStatus: 'NEEDS REVIEW',
      });
    }
  }

  if (facts.some((fact) => fact.integrityStatus === 'SHA-256 verification failed')) {
    throw new Error('Evidence integrity verification failed. Copilot context was not created.');
  }
  if (!facts.length) throw new Error('Selected evidence has no supported structured facts to analyze.');
  return facts;
}

export function validateCopilotResponse(response, facts) {
  if (!response || !Array.isArray(response.interpretations)
    || !Array.isArray(response.investigativeLeads)
    || !Array.isArray(response.recommendations)) {
    throw new Error('The AI service returned an invalid response format.');
  }
  const knownReferences = new Set(facts.map((fact) => fact.referenceId));
  const unsupportedClaims = [];
  const filterClaims = (claims, category) => claims.flatMap((claim) => {
    const text = typeof claim?.text === 'string' ? claim.text.trim().slice(0, 1_000) : '';
    const references = Array.isArray(claim?.evidenceRefs) ? claim.evidenceRefs : [];
    if (!text || !references.length || references.some((reference) => !knownReferences.has(reference))) {
      unsupportedClaims.push({
        category,
        text: text || 'The AI returned a claim without usable text.',
        reason: !references.length ? 'No evidence references were supplied.' : 'One or more evidence references are unknown.',
      });
      return [];
    }
    return [{ text, evidenceRefs: [...new Set(references)] }];
  });
  if (Array.isArray(response.unsupportedClaims)) {
    for (const claim of response.unsupportedClaims.slice(0, 100)) {
      if (typeof claim?.text === 'string' && typeof claim?.reason === 'string') {
        unsupportedClaims.push({
          category: boundedText(claim.category || 'AI claim', 80),
          text: claim.text.slice(0, 1_000),
          reason: claim.reason.slice(0, 300),
        });
      }
    }
  }

  return {
    observedEvidence: facts,
    interpretations: filterClaims(response.interpretations, 'AI Interpretation'),
    investigativeLeads: filterClaims(response.investigativeLeads, 'Investigative Lead'),
    recommendations: filterClaims(response.recommendations, 'Recommendation'),
    unsupportedClaims,
    insufficientEvidence: response.insufficientEvidence === true || unsupportedClaims.length > 0,
    validationStatus: 'NEEDS REVIEW',
  };
}

export function validateCopilotQuestion(question, facts, caseNumber = '') {
  if (typeof question !== 'string' || !question.trim()) throw new Error('Enter an investigation question.');
  if (question.trim().length > MAX_QUESTION_LENGTH) throw new Error('The question must be 2,000 characters or fewer.');
  const request = { question: question.trim(), facts };
  if (getCopilotRequestSize(request.question, facts, caseNumber) > MAX_COPILOT_REQUEST_BYTES) {
    throw new Error('Selected evidence facts exceed the 20 KB Copilot request limit.');
  }
  return request;
}

export function getCopilotRequestSize(question, facts, caseNumber = '') {
  return new TextEncoder().encode(JSON.stringify({
    action: 'ask',
    caseNumber,
    question: question.trim(),
    facts,
  })).byteLength;
}

export function partitionCopilotFacts(question, facts, caseNumber = '') {
  const validatedQuestion = validateCopilotQuestion(question, [], caseNumber).question;
  if (!Array.isArray(facts) || !facts.length) throw new Error('Select at least one evidence fact.');

  const batches = [];
  let batch = [];
  for (const fact of facts) {
    const candidate = [...batch, fact];
    if (getCopilotRequestSize(validatedQuestion, candidate, caseNumber) <= MAX_COPILOT_REQUEST_BYTES) {
      batch = candidate;
      continue;
    }

    if (!batch.length) {
      throw new Error(`Evidence fact ${fact.referenceId || '(unknown)'} exceeds the 20 KB request limit and was not included.`);
    }
    batches.push(batch);
    batch = [fact];
    if (getCopilotRequestSize(validatedQuestion, batch, caseNumber) > MAX_COPILOT_REQUEST_BYTES) {
      throw new Error(`Evidence fact ${fact.referenceId || '(unknown)'} exceeds the 20 KB request limit and was not included.`);
    }
  }
  if (batch.length) batches.push(batch);
  return batches;
}

export function combineCopilotResponses(responses) {
  if (!Array.isArray(responses) || !responses.length) {
    throw new Error('No Copilot batch responses are available to combine.');
  }
  return {
    observedEvidence: responses.flatMap((response) => response.observedEvidence),
    interpretations: responses.flatMap((response) => response.interpretations),
    investigativeLeads: responses.flatMap((response) => response.investigativeLeads),
    recommendations: responses.flatMap((response) => response.recommendations),
    unsupportedClaims: responses.flatMap((response) => response.unsupportedClaims),
    insufficientEvidence: responses.some((response) => response.insufficientEvidence),
    validationStatus: 'NEEDS REVIEW',
  };
}

async function responseJson(response) {
  const text = await response.text();
  if (new TextEncoder().encode(text).byteLength > MAX_RESPONSE_BYTES) throw new Error('The AI response exceeded the 64 KB limit.');
  try {
    return JSON.parse(text);
  } catch {
    throw new Error('The AI service returned an unreadable response.');
  }
}

export async function callCopilot({
  supabaseUrl,
  publishableKey,
  accessToken,
  action,
  payload = {},
  fetchImpl = fetch,
  timeoutMs = REQUEST_TIMEOUT_MS,
}) {
  if (!supabaseUrl || !publishableKey) throw new Error(COPILOT_UNAVAILABLE_MESSAGE);
  if (!accessToken) throw new Error('Sign in with an authorized investigation account to use AI Copilot.');
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetchImpl(`${supabaseUrl.replace(/\/$/, '')}/functions/v1/ai-forensic-copilot`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        apikey: publishableKey,
        Authorization: `Bearer ${accessToken}`,
      },
      body: JSON.stringify({ action, ...payload }),
      signal: controller.signal,
    });
    const data = await responseJson(response);
    if (!response.ok) {
      if (response.status === 401 || response.status === 403) {
        throw new Error(typeof data.error === 'string'
          ? data.error
          : 'Access denied. Sign in and confirm your case membership.');
      }
      if (response.status === 503) throw new Error(COPILOT_UNAVAILABLE_MESSAGE);
      throw new Error(typeof data.error === 'string' ? data.error : 'The AI service request failed.');
    }
    return data;
  } catch (error) {
    if (error.name === 'AbortError') throw new Error('The AI service request timed out. Try again with fewer selected facts.');
    throw error;
  } finally {
    clearTimeout(timeout);
  }
}

export function makeCopilotQuestion(question, facts, caseNumber = '') {
  const validated = validateCopilotQuestion(question, facts, caseNumber);
  return {
    action: 'ask',
    question: validated.question,
    facts: validated.facts,
  };
}

export function makeCopilotFinding(response, question, facts) {
  return {
    id: crypto.randomUUID(),
    question: question.trim(),
    observedEvidence: facts,
    interpretations: response.interpretations,
    investigativeLeads: response.investigativeLeads,
    recommendations: response.recommendations,
    unsupportedClaims: response.unsupportedClaims,
    validationStatus: 'NEEDS REVIEW',
    createdAt: new Date().toISOString(),
    validationHistory: [],
  };
}
