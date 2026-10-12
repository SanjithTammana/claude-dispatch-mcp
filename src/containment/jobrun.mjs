/**
 * Supervision of a JobRun launcher (JobRun.cs): stop it, and confirm from its report that the
 * Job Object held no live process afterwards. PID disappearance alone never confirms teardown.
 */
import { readFileSync } from 'node:fs';

const JOBRUN_EXIT = { KILLED: 125, UNCONFIRMED: 126, LAUNCH_FAILED: 127 };

function pidAlive(pid) {
  if (!pid) return false;
  try { process.kill(pid, 0); return true; }
  catch (error) { return error.code === 'EPERM'; }
}

export function jobrunCleanup(pid, exited, reportPath, exitCode, rootPid) {
  let report = null, detail;
  try {
    const raw = readFileSync(reportPath, 'utf8');
    detail = `JobRun report: ${raw.trim()}`;
    report = JSON.parse(raw);
  } catch (error) { detail = `JobRun report absent or invalid (${reportPath}): ${error.message}`; }
  const expectedExit = ['kill_request', 'stdin_eof'].includes(report?.killed_by)
    ? JOBRUN_EXIT.KILLED : report?.root_exit_code;
  // A live process at a reused PID makes this fail, never pass: it only ever errs toward "unconfirmed".
  const ok = exited && !pidAlive(pid) && Number.isInteger(exitCode)
    && ![JOBRUN_EXIT.UNCONFIRMED, JOBRUN_EXIT.LAUNCH_FAILED].includes(exitCode)
    && ['root_exit', 'kill_request', 'stdin_eof'].includes(report?.killed_by)
    // Process exit codes are unsigned on the Node side; the report may carry them signed.
    // Normalize only inside the representable Windows exit-code domain; out-of-range values must
    // not alias onto a real code once masked.
    && Number.isInteger(expectedExit) && expectedExit >= -2147483648 && expectedExit <= 4294967295
    && exitCode >= 0 && exitCode <= 4294967295
    && (exitCode >>> 0) === (expectedExit >>> 0)
    && Number.isInteger(rootPid) && rootPid > 0
    && report?.root_pid === rootPid && report?.confirmed === true && report.active_after === 0;
  return { ok, report, detail: ok ? detail : `cleanup unconfirmed: ${detail}; JobRun exited=${exited}; exit=${exitCode}; launched root=${rootPid}` };
}

export async function waitWithin(promise, ms) {
  let timer;
  try {
    return await Promise.race([promise.then(() => true),
      new Promise(resolveWait => { timer = setTimeout(() => resolveWait(false), ms); })]);
  } finally { clearTimeout(timer); }
}

export async function stopJobrun(supervisor, reportPath) {
  const { child, closed } = supervisor;
  if (!supervisor.exited && !supervisor.launchError && !child.stdin.destroyed) {
    try { child.stdin.write('kill\n'); } catch { /* concurrently closed control pipe */ }
  }
  // Last resort: terminate JobRun through the process handle Node holds for it. That handle names
  // this process object, never a PID, so a reused PID cannot be hit; once JobRun has exited the
  // handle is gone and nothing is killed. JobRun holds the only job handle, so its termination closes
  // the job and kill-on-close takes every process in it.
  if (!await waitWithin(closed, 8000) && !supervisor.exited) {
    try { child.kill('SIGKILL'); } catch { /* already exited */ }
    await waitWithin(closed, 1000);
  }
  const cleanup = jobrunCleanup(child.pid, supervisor.exited, reportPath,
                                supervisor.exitCode, supervisor.rootPid);
  if (supervisor.launchError) cleanup.detail += `; JobRun launch error: ${supervisor.launchError}`;
  return cleanup;
}
