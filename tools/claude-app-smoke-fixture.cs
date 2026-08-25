using System;
using System.Linq;
using System.Threading;

public static class ClaudeAppSmokeFixture
{
    public static int Main(string[] args)
    {
        bool proxy = args.Any(value => value.StartsWith("--proxy-server=http://127.0.0.1:", StringComparison.Ordinal));
        bool certificate = args.Any(value => value.StartsWith("--ignore-certificate-errors-spki-list=", StringComparison.Ordinal));
        bool userData = args.Any(value => value.StartsWith("--user-data-dir=", StringComparison.Ordinal));
        if (!proxy || !certificate || !userData)
        {
            return 64;
        }
        Thread.Sleep(5000);
        return 0;
    }
}
