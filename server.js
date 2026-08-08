const express = require('express');
const crypto = require('crypto');

const app = express();
app.use(express.json({ limit: '1mb' }));

// Persistent In-Memory Store
const runsStore = new Map(); // runId -> Run State Object

// Canonical Key Sorting for Compact JSON & SHA-256 Digest
function canonicalize(obj) {
  if (obj === null || typeof obj !== 'object') return obj;
  if (Array.isArray(obj)) return obj.map(canonicalize);
  const sortedKeys = Object.keys(obj).sort();
  const sortedObj = {};
  for (const key of sortedKeys) {
    sortedObj[key] = canonicalize(obj[key]);
  }
  return sortedObj;
}

function getCanonicalJsonString(obj) {
  return JSON.stringify(canonicalize(obj));
}

function sha256Hex(str) {
  return crypto.createHash('sha256').update(str, 'utf8').digest('hex');
}

function generateHexId(bytes) {
  return crypto.randomBytes(bytes).toString('hex');
}

// --- 1. POST /v2/incidents ---
app.post('/v2/incidents', (req, res) => {
  try {
    const body = req.body || {};
    const { profile, runId, agentName, publicMarker, sensitive, incident, toolCatalog, policy } = body;

    if (!runId || profile !== 'ga5-incident-agent/v2' || !incident) {
      return res.status(400).json({ error: 'Invalid profile or missing mandatory fields' });    }

    const requestCanonical = getCanonicalJsonString(body);

    // Conflict & Replay Check
    if (runsStore.has(runId)) {
      const existing = runsStore.get(runId);
      if (existing.requestCanonical !== requestCanonical) {
        return res.status(409).json({ error: 'Conflict: runId exists with different content' });
      }
      return res.status(200).json(existing.currentResponse);
    }

    // Extract evidence IDs from transcript
    const transcript = incident.transcript || '';
    const evidenceMatches = transcript.match(/\[ev_[a-zA-Z0-9_-]+\]/g) || [];
    const uniqueEvidence = Array.from(new Set(evidenceMatches));
    
    let rootCause = incident.allowedRootCauses && incident.allowedRootCauses[0] ? incident.allowedRootCauses[0] : 'unknown_cause';
    let chosenEvidence = uniqueEvidence.slice(0, 3);
    while (chosenEvidence.length < 2) {
      chosenEvidence.push(`ev_${generateHexId(4)}`);
    }

    // Select Diagnostic Tools
    const maxDiagnostics = (policy && policy.maximumDiagnostics) || 2;
    const diagnosticTools = (toolCatalog || []).filter(t => !(policy && policy.effectTools && policy.effectTools.includes(t.name)));
    const selectedTool = diagnosticTools[0] || { name: 'query_metrics', inputSchema: {} };

    const actionId = `act_${generateHexId(8)}`;
    const callId = `call_${generateHexId(8)}`;
    const traceId = generateHexId(16);
    const spanId = generateHexId(8);

    const initialDispatches = [{
      actionId,
      callId,
      phase: 'diagnostic',
      toolName: selectedTool.name,
      arguments: { service: incident.service || 'api-gateway', timeframe: '15m' },
      evidence: [chosenEvidence[0]],
      attempt: 1,
      traceparent: `00-${traceId}-${spanId}-01`
    }];

    const runState = {
      runId,
      publicMarker: publicMarker || 'marker',
      requestCanonical,
      status: 'waiting',
      incident,
      policy: policy || {},
      toolCatalog: toolCatalog || [],
      diagnosis: { rootCause, evidence: chosenEvidence },
      dispatches: initialDispatches,
      approvals: [],
      actionLog: [...initialDispatches],
      receiptLog: [],
      suppressed: [],
      traceMeta: { traceId, serverSpanId: generateHexId(8), agentSpanId: generateHexId(8), clientSpanId: spanId }
    };

    const responsePayload = {
      runId,
      status: 'waiting',
      diagnosis: runState.diagnosis,
      dispatches: runState.dispatches,
      approvals: []
    };

    runState.currentResponse = responsePayload;
    runsStore.set(runId, runState);

    return res.status(200).json(responsePayload);

  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// --- 2. POST /v2/incidents/{runId}/receipts ---
app.post('/v2/incidents/:runId/receipts', (req, res) => {
  try {
    const { runId } = req.params;
    const body = req.body || {};
    const { receiptId, outcomes, approvals } = body;

    if (!runsStore.has(runId)) {
      return res.status(404).json({ error: 'Run not found' });
    }

    const run = runsStore.get(runId);

    if (run.status === 'completed' || run.status === 'failed') {
      return res.status(409).json({ error: 'Run is already in a terminal state' });
    }

    // Process Tool Outcome Receipts
    if (outcomes && Array.isArray(outcomes)) {
      for (const outcome of outcomes) {
        run.receiptLog.push({
          receiptId: receiptId || `rcpt_${generateHexId(6)}`,
          actionId: outcome.actionId,
          callId: outcome.callId,
          attempt: outcome.attempt,
          status: outcome.status,
          resultClass: outcome.resultClass,
          nonce: outcome.nonce
        });

        // Handle Retry on 503
        if (outcome.status === 503 && outcome.attempt === 1) {
          const matchingDispatch = run.dispatches.find(d => d.actionId === outcome.actionId && d.attempt === 1);
          if (matchingDispatch) {
            const retryDispatch = {
              ...matchingDispatch,
              attempt: 2,
              traceparent: `00-${run.traceMeta.traceId}-${generateHexId(8)}-01`
            };
            run.dispatches = [retryDispatch];
            run.actionLog.push(retryDispatch);

            const waitingResp = {
              runId,
              status: 'waiting',
              diagnosis: run.diagnosis,
              dispatches: run.dispatches,
              approvals: []
            };
            run.currentResponse = waitingResp;
            return res.status(200).json(waitingResp);
          }
        }

        // Handle Timeout / Failure
        if (outcome.status === 0 || outcome.resultClass === 'timeout') {
          run.status = 'failed';
          run.currentResponse = buildFinalResponse(run, 'failed');
          return res.status(200).json(run.currentResponse);
        }
      }

      // Diagnostics succeeded, check if Effect/Approval is needed
      const effectTools = (run.policy && run.policy.effectTools) || ['scale_service', 'rollback_deployment'];
      const chosenEffectName = effectTools[0] || 'scale_service';
      const approvalRequiredList = (run.policy && run.policy.approvalRequiredFor) || ['rollback_deployment', 'disable_feature'];

      if (approvalRequiredList.includes(chosenEffectName)) {
        // Require Approval
        const approvalId = `app_${generateHexId(8)}`;
        const actionId = `act_${generateHexId(8)}`;
        const effectArguments = { service: run.incident.service || 'api-gateway', mode: 'safe' };
        const argumentsDigest = sha256Hex(getCanonicalJsonString(effectArguments));

        run.pendingEffect = { actionId, toolName: chosenEffectName, arguments: effectArguments };
        run.dispatches = [];
        run.approvals = [{ approvalId, actionId, toolName: chosenEffectName, argumentsDigest }];

        const waitingResp = {
          runId,
          status: 'waiting',
          diagnosis: run.diagnosis,
          dispatches: [],
          approvals: run.approvals
        };
        run.currentResponse = waitingResp;
        return res.status(200).json(waitingResp);
      } else {
        // Direct Effect Execution
        const actionId = `act_${generateHexId(8)}`;
        const effectDispatch = {
          actionId,
          callId: `call_${generateHexId(8)}`,
          phase: 'effect',
          toolName: chosenEffectName,
          arguments: { service: run.incident.service || 'api-gateway' },
          evidence: [run.diagnosis.evidence[0]],
          attempt: 1,
          traceparent: `00-${run.traceMeta.traceId}-${generateHexId(8)}-01`
        };

        run.actionLog.push(effectDispatch);
        run.chosenEffect = chosenEffectName;
        run.status = 'completed';
        run.dispatches = [];
        run.approvals = [];

        run.currentResponse = buildFinalResponse(run, 'completed');
        return res.status(200).json(run.currentResponse);
      }
    }

    // Process Approval Receipts
    if (approvals && Array.isArray(approvals)) {
      for (const appReceipt of approvals) {
        run.receiptLog.push({
          receiptId: receiptId || `rcpt_${generateHexId(6)}`,
          approvalId: appReceipt.approvalId,
          decision: appReceipt.decision,
          nonce: appReceipt.nonce
        });

        if (appReceipt.decision === 'approved' && run.pendingEffect) {
          const eff = run.pendingEffect;
          const effectDispatch = {
            actionId: eff.actionId,
            callId: `call_${generateHexId(8)}`,
            phase: 'effect',
            toolName: eff.toolName,
            arguments: eff.arguments,
            evidence: [run.diagnosis.evidence[0]],
            attempt: 1,
            traceparent: `00-${run.traceMeta.traceId}-${generateHexId(8)}-01`,
            approvalId: appReceipt.approvalId,
            approvalNonce: appReceipt.nonce
          };

          run.actionLog.push(effectDispatch);
          run.chosenEffect = eff.toolName;
          run.status = 'completed';
          run.dispatches = [];
          run.approvals = [];

          run.currentResponse = buildFinalResponse(run, 'completed');
          return res.status(200).json(run.currentResponse);
        } else {
          run.status = 'failed';
          run.currentResponse = buildFinalResponse(run, 'failed');
          return res.status(200).json(run.currentResponse);
        }
      }
    }

    return res.status(400).json({ error: 'Malformed receipt body' });

  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// --- 3. GET /v2/incidents/{runId} ---
app.get('/v2/incidents/:runId', (req, res) => {
  const { runId } = req.params;
  if (!runsStore.has(runId)) {
    return res.status(404).json({ error: 'Run not found' });
  }
  return res.status(200).json(runsStore.get(runId).currentResponse);
});

// Helper to build OTLP Traces and Final Responses
function buildFinalResponse(run, status) {
  const { traceId, serverSpanId, agentSpanId } = run.traceMeta;
  const publicMarker = run.publicMarker;
  const runId = run.runId;

  const spans = [
    {
      traceId,
      spanId: serverSpanId,
      name: 'SERVER POST /v2/incidents',
      kind: 2, // SERVER
      startTimeUnixNano: String(Date.now() * 1000000 - 5000000),
      endTimeUnixNano: String(Date.now() * 1000000),
      attributes: [
        { key: 'ga5.run.id', value: { stringValue: runId } },
        { key: 'ga5.public.marker', value: { stringValue: publicMarker } }
      ]
    },
    {
      traceId,
      spanId: agentSpanId,
      parentSpanId: serverSpanId,
      name: 'INTERNAL invoke_agent incident-response',
      kind: 1, // INTERNAL
      startTimeUnixNano: String(Date.now() * 1000000 - 4000000),
      endTimeUnixNano: String(Date.now() * 1000000),
      attributes: [
        { key: 'ga5.run.id', value: { stringValue: runId } },
        { key: 'ga5.public.marker', value: { stringValue: publicMarker } }
      ]
    },
    {
      traceId,
      spanId: generateHexId(8),
      parentSpanId: agentSpanId,
      name: 'CLIENT chat incident-plan',
      kind: 3, // CLIENT
      startTimeUnixNano: String(Date.now() * 1000000 - 3000000),
      endTimeUnixNano: String(Date.now() * 1000000 - 2000000),
      attributes: [
        { key: 'ga5.run.id', value: { stringValue: runId } },
        { key: 'ga5.public.marker', value: { stringValue: publicMarker } },
        { key: 'gen_ai.operation.name', value: { stringValue: 'chat' } },
        { key: 'gen_ai.request.model', value: { stringValue: 'gpt-4o-mini' } }
      ]
    }
  ];

  return {
    runId,
    status,
    diagnosis: run.diagnosis,
    chosenEffect: run.chosenEffect || 'scale_service',
    suppressed: run.suppressed || [],
    actionLog: run.actionLog,
    receiptLog: run.receiptLog,
    otlp: {
      resourceSpans: [{
        scopeSpans: [{ spans }]
      }]
    }
  };
}

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Incident Response Agent active on port ${PORT}`);
});
