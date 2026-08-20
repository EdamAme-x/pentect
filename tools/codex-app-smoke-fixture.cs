using System;
using System.Diagnostics;
using System.Threading;

public static class CodexAppSmokeFixture
{
    private const string ChildMarker = "PENTECT_CODEX_APP_SMOKE_CHILD";

    public static int Main(string[] args)
    {
        if (Environment.GetEnvironmentVariable(ChildMarker) == "1")
        {
            Thread.Sleep(5000);
            return 0;
        }

        string executable = Process.GetCurrentProcess().MainModule.FileName;
        var start = new ProcessStartInfo(executable)
        {
            CreateNoWindow = true,
            UseShellExecute = false,
        };
        start.EnvironmentVariables[ChildMarker] = "1";
        Process child = Process.Start(start);
        if (child == null)
        {
            return 70;
        }
        return 0;
    }
}
