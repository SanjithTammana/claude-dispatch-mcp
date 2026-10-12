// Test fixtures compiled with the in-box .NET Framework C# compiler (the same one JobRun uses).
import { spawnSync } from "node:child_process";
import { writeFileSync } from "node:fs";
import { join } from "node:path";

const CSC = "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\csc.exe";

export function compileExe(dir, name, source) {
  const cs = join(dir, `${name}.cs`), exe = join(dir, `${name}.exe`);
  writeFileSync(cs, source);
  const r = spawnSync(CSC, ["/nologo", "/target:exe", `/out:${exe}`, cs], { encoding: "utf8", windowsHide: true });
  if (r.status !== 0) throw new Error(`fixture compile failed: ${r.stdout || r.stderr}`);
  return exe;
}

/** An executable that records that it ran (a file next to itself) and exits 1. */
export function markerExe(dir, name) {
  return compileExe(dir, name, `using System.IO;
class P { static int Main() {
  File.WriteAllText(System.Reflection.Assembly.GetExecutingAssembly().Location + ".ran", "ran");
  return 1; } }`);
}

/**
 * A stand-in for JobRun that writes a confirmed report, prints `stdout` text, starts a child that
 * inherits (and so holds open) the standard output pipe, records the child's PID, and exits 0.
 * Usage matches JobRun: --report <path> -- ...
 */
export function pipeHolderExe(dir, name, stdout) {
  return compileExe(dir, name, `using System; using System.Diagnostics; using System.IO;
class P { static int Main(string[] a) {
  File.WriteAllText(a[1], "{\\"root_pid\\":1,\\"root_exit_code\\":0,\\"killed_by\\":\\"root_exit\\",\\"descendants_terminated\\":0,\\"active_after\\":0,\\"confirmed\\":true,\\"error\\":\\"\\"}");
  Console.Out.Write(${JSON.stringify(stdout)}); Console.Out.Flush();
  var psi = new ProcessStartInfo(Environment.SystemDirectory + "\\\\PING.EXE", "-n 40 127.0.0.1"); psi.UseShellExecute = false;
  var child = Process.Start(psi);
  File.WriteAllText(a[1] + ".child", child.Id.ToString());
  return 0; } }`);
}
