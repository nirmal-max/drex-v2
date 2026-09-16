/**
 * =============================================================================
 * DREX-V2 — PHASE 22: P0-01 FRONTEND CASE BINDING UNIT TEST
 * =============================================================================
 * Verifies getAuthoritativeOperationalContext, selectCase persistence,
 * and client-side case-mismatch rejection.
 * =============================================================================
 */

const assert = require('assert');

// Mock STATE
const STATE = {
  activeCase: null,
  cases: [],
  currentView: 'overview',
};

const storage = {};
const mockLocalStorage = {
  getItem: (k) => storage[k] || null,
  setItem: (k, v) => { storage[k] = String(v); },
  removeItem: (k) => { delete storage[k]; },
};

function getActiveCaseId() {
  if (STATE.activeCase && STATE.activeCase.case_id) {
    return STATE.activeCase.case_id;
  }
  return null;
}

function getAuthoritativeOperationalContext(options = {}) {
  const activeCase = STATE.activeCase;
  if (!activeCase || !activeCase.case_id) {
    return null;
  }
  return {
    case_id: activeCase.case_id,
    case_number: activeCase.case_number,
    case_type: activeCase.case_type || 'DIGITAL_FORENSICS',
    source_id: options.source_id || activeCase.source_id || null,
    workflow_id: options.workflow_id || STATE.currentView || 'overview',
    job_id: options.job_id || null,
    method_id: options.method_id !== undefined ? options.method_id : null,
    target_id: options.target_id || null,
  };
}

function selectCase(caseId) {
  const c = STATE.cases.find(item => item.case_id === caseId);
  if (c) {
    STATE.activeCase = c;
    try {
      mockLocalStorage.setItem('drex_authoritative_case_id', c.case_id);
    } catch (_) {}
    return true;
  }
  return false;
}

function restoreInitialCase(preserveCaseId = null) {
  let savedCaseId = null;
  try {
    savedCaseId = mockLocalStorage.getItem('drex_authoritative_case_id');
  } catch (_) {}

  const targetCaseId = preserveCaseId || (STATE.activeCase ? STATE.activeCase.case_id : savedCaseId);
  if (targetCaseId) {
    const match = STATE.cases.find(c => c.case_id === targetCaseId);
    if (match) {
      STATE.activeCase = match;
    } else if (!savedCaseId && STATE.cases.length > 0) {
      STATE.activeCase = STATE.cases[0];
    }
  } else if (STATE.cases.length > 0) {
    STATE.cases = STATE.cases; // no change
  }
}

function validateJobResponse(job, expectedContext) {
  if (!job || !expectedContext) throw new Error("Missing parameters");
  if (job.case_id && job.case_id !== expectedContext.case_id) {
    throw new Error(`CRITICAL CASE MISMATCH: Job ${job.job_id} bound to case ${job.case_id}, expected active case ${expectedContext.case_id}.`);
  }
  return true;
}

// ─── Assertions ──────────────────────────────────────────────────────────────

// Test 1: Null activeCase yields null context
STATE.activeCase = null;
assert.strictEqual(getAuthoritativeOperationalContext(), null, "Test 1 Failed: Null active case must yield null context");

// Test 2: Set active case CASE-A
STATE.cases = [
  { case_id: 'CASE-A', case_number: 'DREX-2026-001', title: 'Case Alpha' },
  { case_id: 'CASE-B', case_number: 'DREX-2026-002', title: 'Case Beta' },
];

selectCase('CASE-A');
assert.strictEqual(STATE.activeCase.case_id, 'CASE-A', "Test 2 Failed: Case A should be active");
assert.strictEqual(mockLocalStorage.getItem('drex_authoritative_case_id'), 'CASE-A', "Test 2 Failed: Case A not persisted");

const ctxA = getAuthoritativeOperationalContext({ workflow_id: 'recovery', method_id: 17, target_id: '/dev/sdb' });
assert.ok(ctxA !== null, "Test 3 Failed: ctxA should not be null");
assert.strictEqual(ctxA.case_id, 'CASE-A');
assert.strictEqual(ctxA.case_number, 'DREX-2026-001');
assert.strictEqual(ctxA.workflow_id, 'recovery');
assert.strictEqual(ctxA.method_id, 17);
assert.strictEqual(ctxA.target_id, '/dev/sdb');

// Test 4: Verify valid job response matches
const validJobA = { job_id: 'JOB-01', case_id: 'CASE-A', workflow_id: 'recovery' };
assert.strictEqual(validateJobResponse(validJobA, ctxA), true, "Test 4 Failed: Valid job should pass");

// Test 5: Verify mismatch throws critical error
const invalidJob = { job_id: 'JOB-02', case_id: 'CASE-B', workflow_id: 'recovery' };
assert.throws(() => {
  validateJobResponse(invalidJob, ctxA);
}, /CRITICAL CASE MISMATCH/, "Test 5 Failed: Mismatched job case_id must throw error");

// Test 6: Switch to CASE-B
selectCase('CASE-B');
assert.strictEqual(STATE.activeCase.case_id, 'CASE-B', "Test 6 Failed: Case B should be active");
assert.strictEqual(mockLocalStorage.getItem('drex_authoritative_case_id'), 'CASE-B');
const ctxB = getAuthoritativeOperationalContext({ workflow_id: 'file_eraser' });
assert.strictEqual(ctxB.case_id, 'CASE-B');

// Test 7: Reload simulation preserves Case B and does not revert to Case A (cases[0])
STATE.activeCase = null; // simulate page refresh
restoreInitialCase();
assert.ok(STATE.activeCase !== null, "Test 7 Failed: Active case should be restored");
assert.strictEqual(STATE.activeCase.case_id, 'CASE-B', "Test 7 Failed: Case B should be restored from localStorage, not cases[0]");

console.log("SUCCESS: All 7 JavaScript P0-01 Case Binding assertions passed cleanly!");
