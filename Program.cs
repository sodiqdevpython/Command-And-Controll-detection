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

    }
}