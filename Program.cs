using System;
using MyEventTracer;
using CommandAndControll.Services;

namespace CommandAndControll
{
    class Program
    {
        static void Main(string[] args)
        {
            var detector = new C2DetectorService();

            detector.OnAlert += (sender, e) =>
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"\n[ DANGER ] {e.Message}");
                Console.WriteLine($"Target: {e.Process.FullPath}\n");
                Console.ResetColor();
            };

            detector.OnTrafficDetected += (sender, e) =>
            {
                if (e.CurrentScore >= 80)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                }
                else if (e.CurrentScore >= 50)
                {
                    Console.ForegroundColor = ConsoleColor.Magenta;
                }
                else
                {
                    Console.ForegroundColor = e.IsSend ? ConsoleColor.Yellow : ConsoleColor.Cyan;
                }

                string direction = e.IsSend ? "SEND =>" : "RECV <-";

                Console.WriteLine($"PID: {e.Pid,-5} [{e.CurrentScore,3}] {direction} {e.RemoteAddress}:{e.RemotePort,-5} ({e.Size}) | {e.ProcessPath}");

                Console.ResetColor();
            };

            try
            {
                detector.Start();
                Console.ReadLine();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
            finally
            {
                detector.Stop();
            }
        }

        static void Main2(string[] args)
        {
            EventTracer.ClearOldSessions();

            var tracer = EventTracer.Instance;

            tracer.NetworkIOMonitor += OnNetworkEvent;

            tracer.LogMessage += msg => Console.WriteLine($"[LOG] {msg}");
            tracer.ErrorOccurred += err => Console.WriteLine($"[ERROR] {err}");

            tracer.Start(TraceModule.NetworkIO);

            Console.WriteLine("\nMonitoring boshlandi. Chiqish uchun Enter bosing...\n");
            Console.ReadLine();

            tracer.StopAll();
            tracer.Dispose();
            Console.WriteLine("To'xtadi");
        }

        static void OnNetworkEvent(NetworkIOTraceData data)
        {
            var detector = new C2DetectorService();
            if (detector.IsLocalAddress(data.RemoteAddress) == false)

            Console.WriteLine($"[NETWORK {(data.IsSend ? "SEND" : "RECV")}] " +
            $"PID: {data.ProcessId}, {data.LocalAddress}:{data.LocalPort} <-> " +
            $"{data.RemoteAddress}:{data.RemotePort}, Size: {data.Size} \nPath: {data.ProcessImagePath}");
        }

    }
}