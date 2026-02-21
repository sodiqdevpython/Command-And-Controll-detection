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
            detector.OnTrafficDetected += HandleTrafficDetected;

            try
            {
                detector.Start();

                Console.WriteLine("Ishga tushdi...");

                // UI dasturchisi API ni qanday chaqirishini tushunishi uchun kichik namuna
                DemonstrateSnapshot(detector);

                // Dastur yopilib qolmasligi uchun kutib turadi
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

        // 1. UI UCHUN: Qizil Signal (Faqat xavf 70 dan oshganda ishlaydi)
        private static void HandleAlert(object sender, AlertEventArgs e)
        {
            Console.WriteLine($"[ALERT] Xavf aniqlandi! PID: {e.Process.Pid} | Xabar: {e.Message}");
        }

        // 2. UI UCHUN: Progress Bar (Ball o'zgargandagina ishlaydi)
        private static void HandleScoreChanged(object sender, MonitoredProcess proc)
        {
            Console.WriteLine($"[SCORE UPDATE] PID: {proc.Pid} ({proc.ProcessName}) -> Yangi ball: {proc.Score}");
        }

        // 3. UI UCHUN: Tarmoq trafigi loglari (Har bir paket uchun)
        private static void HandleTrafficDetected(object sender, TrafficEventArgs e)
        {
            string direction = e.IsSend ? "SEND =>" : "RECV <-";
            Console.WriteLine($"[TRAFFIC] PID: {e.Pid} | {direction} {e.RemoteAddress}:{e.RemotePort} ({e.Size} bytes)");
        }

        // 4. UI UCHUN: Barcha jarayonlarni ro'yxatini olish (Snapshot)
        private static void DemonstrateSnapshot(C2DetectorService detector)
        {
            // UI dasturchisi xohlagan vaqtida (masalan oynani yangilaganda) shu metodni chaqirib hamma ma'lumotni List qilib oladi
            List<MonitoredProcess> allProcesses = detector.GetAllMonitoredProcesses();
            Console.WriteLine($"[INFO] Hozirda {allProcesses.Count} ta jarayon kuzatilmoqda.\n");
        }
    }
}