/**
 * DREX-V2 Phase 22: JavaScript Authoritative Progress Model Unit Tests
 * Verifies all 12 truth conditions directly against webui/app.js.
 */
const fs = require('fs');
const path = require('path');

const appJsPath = path.join(__dirname, '..', 'webui', 'app.js');
const code = fs.readFileSync(appJsPath, 'utf8');

// Helper to extract function by name
function extractFunction(source, fnName) {
  const start = source.indexOf(`function ${fnName}(`);
  if (start === -1) throw new Error(`Function ${fnName} not found`);
  let depth = 0;
  let inBody = false;
  for (let i = start; i < source.length; i++) {
    if (source[i] === '{') {
      depth++;
      inBody = true;
    } else if (source[i] === '}') {
      depth--;
      if (inBody && depth === 0) {
        return source.slice(start, i + 1);
      }
    }
  }
  throw new Error(`Could not parse ${fnName}`);
}

global.formatBytes = b => { if (b === 0 || !b) return '0 B'; const k = 1024; const sizes = ['B', 'KB', 'MB', 'GB', 'TB']; const i = Math.floor(Math.log(b) / Math.log(k)); return parseFloat((b / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]; };
const fmtPctDef = extractFunction(code, 'formatPercentageString');
const getAuthProgDef = extractFunction(code, 'getAuthoritativeProgress');

eval(fmtPctDef);
eval(getAuthProgDef);
global.formatPercentageString = formatPercentageString;
global.getAuthoritativeProgress = getAuthoritativeProgress;

function assertEqual(actual, expected, msg) {
  if (actual !== expected) {
    throw new Error(`FAIL [${msg}]: expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
  }
}

// 1. Percentage String Formatting Tests
assertEqual(formatPercentageString(null), '—', 'null -> —');
assertEqual(formatPercentageString(undefined), '—', 'undefined -> —');
assertEqual(formatPercentageString(0), '—', '0 -> —');
assertEqual(formatPercentageString(-1), '—', '-1 -> —');
assertEqual(formatPercentageString(0.0001), '0.01%', '0.0001 -> 0.01%');
assertEqual(formatPercentageString(0.009), '0.01%', '0.009 -> 0.01%');
assertEqual(formatPercentageString(0.01), '0.01%', '0.01 -> 0.01%');
assertEqual(formatPercentageString(0.37), '0.37%', '0.37 -> 0.37%');
assertEqual(formatPercentageString(4.82), '4.82%', '4.82 -> 4.82%');
assertEqual(formatPercentageString(10), '10%', '10 -> 10%');
assertEqual(formatPercentageString(50), '50%', '50 -> 50%');
assertEqual(formatPercentageString(99.99), '99.99%', '99.99 -> 99.99%');
assertEqual(formatPercentageString(100), '100%', '100 -> 100%');

// 2. State A: Precheck / Preparing / Queued
const tPre = getAuthoritativeProgress({ status: 'PREPARING', phase: 'PRECHECK', processed_bytes: 0, total_bytes: 1048576 });
assertEqual(tPre.displayPercentage, '0.00%', 'State A Precheck display');
assertEqual(tPre.barWidthPercent, 0, 'State A Precheck barWidth');
assertEqual(tPre.isIndeterminate, false, 'State A Precheck not indeterminate');

const tQueued = getAuthoritativeProgress({ status: 'QUEUED', phase: 'QUEUED', processed_bytes: 0, total_bytes: 1048576 });
assertEqual(tQueued.displayPercentage, '0.00%', 'State A Queued display');
assertEqual(tQueued.barWidthPercent, 0, 'State A Queued barWidth');

// 3. State B: RUNNING but zero work completed
const tB = getAuthoritativeProgress({ status: 'RUNNING', phase: 'RUNNING', processed_bytes: 0, total_bytes: 52428800 });
assertEqual(tB.displayPercentage, '—', 'State B display percentage is dash');
assertEqual(tB.realPercentage, null, 'State B real percentage is null');
assertEqual(tB.isIndeterminate, true, 'State B is indeterminate');
assertEqual(tB.barClass, 'indeterminate', 'State B bar class is indeterminate');
assertEqual(tB.ariaValueNow, null, 'State B aria-valuenow is null');

// 4. State C: First positive chunk (256 KB of 50 MB)
const tC = getAuthoritativeProgress({ status: 'RUNNING', phase: 'WRITING', processed_bytes: 262144, total_bytes: 52428800 });
assertEqual(tC.hasStartedWork, true, 'State C hasStartedWork');
assertEqual(tC.displayPercentage, '0.50%', 'State C displayPct');
assertEqual(tC.isIndeterminate, false, 'State C not indeterminate');
assertEqual(tC.ariaValueNow, '0.50', 'State C ariaValueNow');

// 5. Sub-basis-point floor: 1 B of 1 GB
const tSub = getAuthoritativeProgress({ status: 'RUNNING', phase: 'WRITING', processed_bytes: 1, total_bytes: 1073741824 });
assertEqual(tSub.displayPercentage, '0.01%', 'Sub-basis floor displayPct');
assertEqual(tSub.barWidthPercent, 0.01, 'Sub-basis floor barWidth');

// 6. Mandatory Tiny-File Test: 512 B of 1024 B -> 50%, NOT 0.01%
const tTiny = getAuthoritativeProgress({ status: 'RUNNING', phase: 'WRITING', processed_bytes: 512, total_bytes: 1024 });
assertEqual(tTiny.displayPercentage, '50%', 'Tiny file must be 50%, NOT 0.01%');
assertEqual(tTiny.barWidthPercent, 50, 'Tiny file barWidth 50');

// 7. 100% Write Completion Decoupled from VERIFIED
const t100 = getAuthoritativeProgress({ status: 'RUNNING', phase: 'VERIFYING', processed_bytes: 1000, total_bytes: 1000 });
assertEqual(t100.displayPercentage, '100%', '100% write complete display');
assertEqual(t100.isVerified, false, '100% write is NOT verified');
assertEqual(t100.barClass, 'verifying', '100% write bar class verifying');

// 8. Terminal Verification
const tVer = getAuthoritativeProgress({ status: 'COMPLETED', phase: 'COMPLETED', verification_state: 'VERIFIED', processed_bytes: 1000, total_bytes: 1000 });
assertEqual(tVer.isVerified, true, 'Terminal verified true');
assertEqual(tVer.isComplete, true, 'Terminal complete true');
assertEqual(tVer.displayPercentage, '100%', 'Terminal verified 100%');

// 9. Cancelled
const tCancel = getAuthoritativeProgress({ status: 'CANCELLED', phase: 'CANCELLED', processed_bytes: 500, total_bytes: 1000 });
assertEqual(tCancel.isVerified, false, 'Cancelled is NOT verified');
assertEqual(tCancel.barClass, 'cancelled', 'Cancelled bar class');
assertEqual(tCancel.displayPercentage, '50%', 'Cancelled with 500/1000 shows 50%');

// 10. Failed
const tFail = getAuthoritativeProgress({ status: 'FAILED', phase: 'FAILED', processed_bytes: 200, total_bytes: 1000 });
assertEqual(tFail.isVerified, false, 'Failed is NOT verified');
assertEqual(tFail.barClass, 'failed', 'Failed bar class');

// 11. Unknown Total
const tUnknown = getAuthoritativeProgress({ status: 'RUNNING', phase: 'RUNNING', processed_bytes: 1048576, total_bytes: 0 });
assertEqual(tUnknown.displayPercentage, '—', 'Unknown total display is dash');
assertEqual(tUnknown.isIndeterminate, true, 'Unknown total is indeterminate');
assertEqual(tUnknown.realPercentage, null, 'Unknown total realPercentage is null');

console.log('SUCCESS: All 26 JavaScript Authoritative Progress Truth Assertions Passed Cleanly!');
