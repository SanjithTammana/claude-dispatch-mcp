using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

internal static class JobRun
{
    private const int Killed = 125, Unconfirmed = 126, LaunchFailed = 127;
    private const uint KillOnClose = 0x2000, Suspended = 4, UnicodeEnvironment = 0x400;
    private const uint ExtendedStartup = 0x80000, UseStdHandles = 0x100;
    // A detached JobRun has no console; without this a console worker gets a new, VISIBLE one.
    private const uint NoWindow = 0x08000000;
    private const uint Infinite = 0xffffffff, WaitFailed = 0xffffffff;
    private static readonly IntPtr InvalidHandle = new IntPtr(-1);

    [StructLayout(LayoutKind.Sequential)]
    private struct BasicLimits
    {
        public long ProcessTime, JobTime;
        public uint Flags;
        public UIntPtr MinWorkingSet, MaxWorkingSet;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass, SchedulingClass;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct IoCounters { public ulong ReadOps, WriteOps, OtherOps, ReadBytes, WriteBytes, OtherBytes; }
    [StructLayout(LayoutKind.Sequential)]
    private struct ExtendedLimits
    {
        public BasicLimits Basic;
        public IoCounters Io;
        public UIntPtr ProcessMemory, JobMemory, PeakProcessMemory, PeakJobMemory;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct Accounting
    {
        public long UserTime, KernelTime, PeriodUserTime, PeriodKernelTime;
        public uint PageFaults, TotalProcesses, ActiveProcesses, TotalTerminatedProcesses;
    }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct StartupInfo
    {
        public uint Size;
        public IntPtr Reserved, Desktop, Title;
        public uint X, Y, XSize, YSize, XChars, YChars, FillAttribute, Flags;
        public ushort ShowWindow, ReservedSize;
        public IntPtr ReservedBytes, Stdin, Stdout, Stderr;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct StartupInfoEx { public StartupInfo Startup; public IntPtr Attributes; }
    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessInfo { public IntPtr Process, Thread; public uint Pid, Tid; }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateJobObjectW(IntPtr attributes, string name);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetInformationJobObject(IntPtr job, int infoClass, ref ExtendedLimits info, uint size);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool QueryInformationJobObject(IntPtr job, int infoClass, out Accounting info, uint size, IntPtr returned);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool TerminateJobObject(IntPtr job, uint code);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CreateProcessW(string application, StringBuilder command, IntPtr processAttributes,
        IntPtr threadAttributes, bool inherit, uint flags, IntPtr environment, string cwd,
        ref StartupInfoEx startup, out ProcessInfo process);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint ResumeThread(IntPtr thread);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool TerminateProcess(IntPtr process, uint code);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetExitCodeProcess(IntPtr process, out uint code);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(IntPtr handle, uint ms);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForMultipleObjects(uint count, IntPtr[] handles, bool all, uint ms);
    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll")]
    private static extern IntPtr GetStdHandle(int which);
    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DuplicateHandle(IntPtr sourceProcess, IntPtr source, IntPtr targetProcess,
        out IntPtr target, uint access, bool inherit, uint options);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateFileW(string name, uint access, uint share, IntPtr security,
        uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool InitializeProcThreadAttributeList(IntPtr list, int count, uint flags, ref IntPtr size);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool UpdateProcThreadAttribute(IntPtr list, uint flags, IntPtr attribute,
        IntPtr value, IntPtr size, IntPtr previous, IntPtr returned);
    [DllImport("kernel32.dll")]
    private static extern void DeleteProcThreadAttributeList(IntPtr list);

    private static void Check(bool ok, string call)
    {
        if (!ok)
        {
            int code = Marshal.GetLastWin32Error();
            throw new Win32Exception(code, call + " failed (" + code + "): " + new Win32Exception(code).Message);
        }
    }
    private static IntPtr InheritableCopy(IntPtr handle)
    {
        IntPtr copy;
        Check(DuplicateHandle(GetCurrentProcess(), handle, GetCurrentProcess(), out copy, 0, true, 2), "DuplicateHandle");
        return copy;
    }
    // CRT / CommandLineToArgvW quoting: double backslashes before quotes and the closing quote.
    private static string Quote(string arg)
    {
        StringBuilder result = new StringBuilder("\"");
        int slashes = 0;
        foreach (char c in arg)
        {
            if (c == '\\') { slashes++; continue; }
            result.Append('\\', c == '"' ? slashes * 2 + 1 : slashes);
            result.Append(c);
            slashes = 0;
        }
        result.Append('\\', slashes * 2);
        return result.Append('"').ToString();
    }
    private static string JsonString(string value)
    {
        StringBuilder result = new StringBuilder("\"");
        foreach (char c in value)
        {
            if (c == '"' || c == '\\') result.Append('\\').Append(c);
            else if (c < 32) result.Append("\\u").Append(((int)c).ToString("x4"));
            else result.Append(c);
        }
        return result.Append('"').ToString();
    }
    private static Accounting ReadAccounting(IntPtr job)
    {
        Accounting info;
        Check(QueryInformationJobObject(job, 1, out info, (uint)Marshal.SizeOf(typeof(Accounting)), IntPtr.Zero),
              "QueryInformationJobObject");
        return info;
    }

    private static int Main(string[] args)
    {
        if (args.Length < 4 || args[0] != "--report" || args[2] != "--")
        {
            Console.Error.WriteLine("usage: JobRun.exe --report <path> -- <exe> [args...]");
            return LaunchFailed;
        }
        string reportPath = Path.GetFullPath(args[1]);
        // Never launch behind a report planted before preflight (including read-only files).
        if (File.Exists(reportPath) || Directory.Exists(reportPath))
        {
            Console.Error.WriteLine("JobRun refuses existing report path: " + reportPath);
            return LaunchFailed;
        }
        IntPtr job = IntPtr.Zero, nul = IntPtr.Zero, input = IntPtr.Zero, output = IntPtr.Zero, errorHandle = IntPtr.Zero;
        IntPtr attributes = IntPtr.Zero, handleList = IntPtr.Zero;
        bool attributesInitialized = false, assigned = false, launched = false, confirmed = false;
        ProcessInfo process = new ProcessInfo();
        int? rootExit = null;
        int activeAfter = -1, descendants = 0, exit = LaunchFailed;
        string reason = "assign_failed", error = "";
        ManualResetEvent request = new ManualResetEvent(false);
        int requestKind = 0;
        try
        {
            job = CreateJobObjectW(IntPtr.Zero, null); // Unnamed and non-inheritable.
            Check(job != IntPtr.Zero, "CreateJobObject");
            ExtendedLimits limits = new ExtendedLimits();
            limits.Basic.Flags = KillOnClose; // No BREAKAWAY_OK or SILENT_BREAKAWAY_OK.
            Check(SetInformationJobObject(job, 9, ref limits, (uint)Marshal.SizeOf(typeof(ExtendedLimits))),
                  "SetInformationJobObject");
            nul = CreateFileW("NUL", 0x80000000, 3, IntPtr.Zero, 3, 0, IntPtr.Zero);
            Check(nul != InvalidHandle, "CreateFile(NUL)");
            input = InheritableCopy(nul);
            output = InheritableCopy(GetStdHandle(-11));
            errorHandle = InheritableCopy(GetStdHandle(-12));
            // Inherit exactly these three handles, never the control pipe or the job handle.
            IntPtr bytes = IntPtr.Zero;
            InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref bytes);
            attributes = Marshal.AllocHGlobal(bytes);
            Check(InitializeProcThreadAttributeList(attributes, 1, 0, ref bytes), "InitializeProcThreadAttributeList");
            attributesInitialized = true;
            handleList = Marshal.AllocHGlobal(IntPtr.Size * 3);
            Marshal.WriteIntPtr(handleList, 0, input);
            Marshal.WriteIntPtr(handleList, IntPtr.Size, output);
            Marshal.WriteIntPtr(handleList, IntPtr.Size * 2, errorHandle);
            Check(UpdateProcThreadAttribute(attributes, 0, new IntPtr(0x20002), handleList,
                new IntPtr(IntPtr.Size * 3), IntPtr.Zero, IntPtr.Zero), "UpdateProcThreadAttribute(HANDLE_LIST)");
            StartupInfoEx startup = new StartupInfoEx();
            startup.Startup.Size = (uint)Marshal.SizeOf(typeof(StartupInfoEx));
            startup.Startup.Flags = UseStdHandles;
            startup.Startup.Stdin = input; startup.Startup.Stdout = output; startup.Startup.Stderr = errorHandle;
            startup.Attributes = attributes;
            StringBuilder command = new StringBuilder();
            for (int i = 3; i < args.Length; i++) { if (i > 3) command.Append(' '); command.Append(Quote(args[i])); }
            Check(CreateProcessW(args[3], command, IntPtr.Zero, IntPtr.Zero, true,
                Suspended | UnicodeEnvironment | ExtendedStartup | NoWindow, IntPtr.Zero, null, ref startup, out process),
                "CreateProcess");
            launched = true;
            Check(AssignProcessToJobObject(job, process.Process), "AssignProcessToJobObject");
            assigned = true;
            reason = "runtime_failed";
            // The worker is still suspended: this is necessarily the first stderr line.
            Console.Error.WriteLine("jobrun_root_pid=" + process.Pid);
            Console.Error.Flush();
            Check(ResumeThread(process.Thread) != uint.MaxValue, "ResumeThread");
            Thread control = new Thread(delegate()
            {
                try
                {
                    string line;
                    while ((line = Console.ReadLine()) != null)
                    {
                        if (line != "kill") continue;
                        Interlocked.CompareExchange(ref requestKind, 1, 0); request.Set(); return;
                    }
                    Interlocked.CompareExchange(ref requestKind, 2, 0); request.Set();
                }
                catch (IOException) { Interlocked.CompareExchange(ref requestKind, 2, 0); request.Set(); }
                catch (ObjectDisposedException) { }
            });
            control.IsBackground = true;
            control.Start();
            uint waited = WaitForMultipleObjects(2, new IntPtr[] { process.Process, request.SafeWaitHandle.DangerousGetHandle() },
                                                false, Infinite);
            Check(waited != WaitFailed && waited <= 1, "WaitForMultipleObjects");
            bool rootGone = waited == 0;
            reason = rootGone ? "root_exit" : (requestKind == 1 ? "kill_request" : "stdin_eof");
            if (rootGone)
            {
                uint code;
                Check(GetExitCodeProcess(process.Process, out code), "GetExitCodeProcess");
                rootExit = unchecked((int)code);
            }
            Accounting before = ReadAccounting(job);
            // Snapshot descendants still active when teardown starts; excludes a live root.
            descendants = Math.Max(0, (int)before.ActiveProcesses - (rootGone ? 0 : 1));
            Check(TerminateJobObject(job, Killed), "TerminateJobObject");
            Stopwatch deadline = Stopwatch.StartNew();
            do
            {
                activeAfter = (int)ReadAccounting(job).ActiveProcesses;
                if (activeAfter == 0) break;
                Thread.Sleep(20);
            } while (deadline.ElapsedMilliseconds < 5000);
            confirmed = activeAfter == 0;
            if (!confirmed) error = "job still active after 5s teardown deadline";
            exit = confirmed ? (rootGone ? rootExit.Value : Killed) : Unconfirmed;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            if (assigned) reason = "runtime_failed";
            confirmed = false;
            exit = assigned ? Unconfirmed : LaunchFailed;
            if (launched && !assigned)
            {
                if (!TerminateProcess(process.Process, LaunchFailed)) error += "; TerminateProcess: " + Marshal.GetLastWin32Error();
                if (WaitForSingleObject(process.Process, 5000) != 0) error += "; suspended process termination unconfirmed";
            }
            if (job != IntPtr.Zero)
            {
                TerminateJobObject(job, Killed);
                try { activeAfter = (int)ReadAccounting(job).ActiveProcesses; } catch { }
            }
        }
        finally
        {
            // This backstop applies even when reporting or a native call fails.
            if (job != IntPtr.Zero) CloseHandle(job);
            if (process.Thread != IntPtr.Zero) CloseHandle(process.Thread);
            if (process.Process != IntPtr.Zero) CloseHandle(process.Process);
            foreach (IntPtr handle in new IntPtr[] { input, output, errorHandle, nul })
                if (handle != IntPtr.Zero && handle != InvalidHandle) CloseHandle(handle);
            if (attributesInitialized) DeleteProcThreadAttributeList(attributes);
            if (attributes != IntPtr.Zero) Marshal.FreeHGlobal(attributes);
            if (handleList != IntPtr.Zero) Marshal.FreeHGlobal(handleList);
            // The background reader may still be blocked; process exit ends it. Do not dispose
            // its event here while it may signal EOF during report publication.
        }
        try
        {
            string json = "{\"root_pid\":" + process.Pid + ",\"root_exit_code\":" +
                (rootExit.HasValue ? rootExit.Value.ToString(System.Globalization.CultureInfo.InvariantCulture) : "null") +
                ",\"killed_by\":" + JsonString(reason) + ",\"descendants_terminated\":" + descendants +
                ",\"active_after\":" + activeAfter + ",\"confirmed\":" + (confirmed ? "true" : "false") +
                ",\"error\":" + JsonString(error) + "}";
            string temp = reportPath + "." + Guid.NewGuid().ToString("N") + ".tmp";
            try
            {
                File.WriteAllText(temp, json + "\n", new UTF8Encoding(false));
                // A worker planting a report during execution must not be able to certify it.
                File.Move(temp, reportPath);
            }
            finally { if (File.Exists(temp)) File.Delete(temp); }
        }
        catch (Exception ex) { Console.Error.WriteLine("JobRun report: " + ex.Message); return Unconfirmed; }
        return exit;
    }
}
