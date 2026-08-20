using System;
using System.ComponentModel;
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
        Process child;
        try
        {
            child = Process.Start(start);
        }
        catch (Win32Exception)
        {
            return 70;
        }
        catch (InvalidOperationException)
        {
            return 70;
        }
        if (child == null)
        {
            return 70;
        }
        return 0;
    }
}
