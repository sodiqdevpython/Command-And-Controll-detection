using CommandAndControl.Models;
using CommandAndControl.Services;
using MyEventTracer;
using System;
using System.Collections.Generic;

namespace CommandAndControll
{
    class Program
    {
        static void Main(string[] args)
        {
            var detector = new C2DetectorService();

            detector.OnAlert += HandleAlert;
            detector.OnScoreChanged += HandleScoreChanged;
            //detector.OnTrafficDetected += HandleTrafficDetected;

            try
            {
                detector.Start();

                Console.WriteLine("Ishga tushdi...");

                Console.ReadLine();
                DemonstrateSnapshot(detector);
                Console.ReadLine();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Xatolik: {ex.Message}");
            }
            finally
            {
                detector.Stop();
                Console.WriteLine("Monitoring to'xtatildi.");
            }
        }


        private static void HandleAlert(object sender, AlertEventArgs e)
        {
            Console.WriteLine($"[ALERT] c2c aniqlandi PID: {e.Process.Pid} | {e.Message}");
        }

        private static void HandleScoreChanged(object sender, MonitoredProcess proc)
        {
            Console.WriteLine($"[SCORE UPDATE] PID: {proc.Pid} ({proc.ProcessName}) ({proc.FullPath}) -> ball: {proc.Score}");
        }

        //private static void HandleTrafficDetected(object sender, TrafficEventArgs e)
        //{
        //    string direction = e.IsSend ? "SEND =>" : "RECV <-";
        //    Console.WriteLine($"[TRAFFIC] PID: {e.Pid} | {direction} {e.RemoteAddress}:{e.RemotePort} ({e.Size} bytes)");
        //}

        // 4. UI UCHUN: Barcha jarayonlarni ro'yxatini olish ga kerak
        private static void DemonstrateSnapshot(C2DetectorService detector)
        {
            List<MonitoredProcess> allProcesses = detector.GetAllMonitoredProcesses();
            Console.WriteLine($"[INFO] {allProcesses.Count} ta jarayon bor\n");
        }
    }
}