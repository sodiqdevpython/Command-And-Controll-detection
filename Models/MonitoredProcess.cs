using System;
using System.Collections.Generic;

namespace CommandAndControll.Models
{
    public class MonitoredProcess
    {
        public int Pid { get; set; }
        public string FullPath { get; set; }
        public string ProcessName { get; set; }

        // Trafik statistikasi
        public ulong SendBytes { get; set; }
        public ulong ReceivedBytes { get; set; }
        public ulong PacketsCount { get; set; }

        // Ball va Sabablari
        public int Score { get; set; }
        public List<string> Reasons { get; set; } = new List<string>();

        // Holatlar (Flags)
        public bool IsInUnusualPath { get; set; }
        public bool IsAutorun { get; set; }
        public bool UsedUnusualPort { get; set; }
        public int RatioPenaltyCount { get; set; } // Max 5

        // file pe ni o'qishim uchun o'zi nimalar chaqirilgan qaysi dll dan qaysi funksiyalarni call qilmoqchi shuni o'qishim uchun
        public bool IsPeChecked { get; set; }
        public bool IsSuspiciouslyPacked { get; set; }
        public Dictionary<string, List<string>> SuspiciousImports { get; set; } = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);

        // Alert bir marta chiqqandan keyin qayta-qayta spam qilmaslik uchun qo'shimcha field
        public bool AlertTriggered { get; set; }

        public MonitoredProcess(int pid, string path, string name)
        {
            Pid = pid;
            FullPath = path;
            ProcessName = name;
            Score = 0;
            IsPeChecked = false;
        }

        public void AddScore(int points, string reason)
        {
            Score += points;
            Reasons.Add($"{reason} (+{points})");
        }
    }
}