using System;
using System.Collections.Generic;
using System.Collections.Concurrent;

namespace CommandAndControl.Models
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
        public ConcurrentQueue<string> Reasons { get; set; } = new ConcurrentQueue<string>();

        private readonly object _scoreLock = new object();
        private readonly object _deadIpLock = new object();

        // Holatlar (Flags)
        public bool IsInUnusualPath { get; set; }
        public bool IsAutorun { get; set; }
        public DateTime FirstSeenTime { get; set; }
        public bool IsLateAutorunChecked { get; set; }

        public bool UsedUnusualPort { get; set; }
        public int RatioPenaltyCount { get; set; } // Max 5

        // file pe ni o'qishim uchun o'zi nimalar chaqirilgan qaysi dll dan qaysi funksiyalarni call qilmoqchi shuni o'qishim uchun
        public bool IsPeChecked { get; set; }
        public bool IsSuspiciouslyPacked { get; set; }
        public Dictionary<string, List<string>> SuspiciousImports { get; set; } = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);

        // Dead ip va portga so'rov yuborayotganlarni saqlashim uchun
        public Dictionary<string, int> UnansweredRequests { get; set; } = new Dictionary<string, int>();
        public HashSet<string> DeadIpsFlagged { get; set; } = new HashSet<string>();

        private Queue<string> _unansweredQueue = new Queue<string>();
        private const int MaxTrackedIps = 100;

        // Alert bir marta chiqqandan keyin qayta-qayta spam qilmaslik uchun qo'shimcha field
        public bool AlertTriggered { get; set; }

        public void RegisterUnansweredRequest(string endpoint)
        {
            lock (_deadIpLock)
            {
                if (!UnansweredRequests.ContainsKey(endpoint))
                {
                    if (_unansweredQueue.Count >= MaxTrackedIps)
                    {
                        string oldestEndpoint = _unansweredQueue.Dequeue();
                        UnansweredRequests.Remove(oldestEndpoint);
                        DeadIpsFlagged.Remove(oldestEndpoint);
                    }

                    _unansweredQueue.Enqueue(endpoint);
                    UnansweredRequests[endpoint] = 0;
                }

                UnansweredRequests[endpoint]++;
            }
        }

        public void ResetUnansweredRequest(string endpoint)
        {
            lock (_deadIpLock)
            {
                if (UnansweredRequests.ContainsKey(endpoint))
                {
                    UnansweredRequests[endpoint] = 0;
                }
            }
        }

        public MonitoredProcess(int pid, string path, string name)
        {
            Pid = pid;
            FullPath = path;
            ProcessName = name;
            Score = 0;
            IsPeChecked = false;
            FirstSeenTime = DateTime.Now;
            IsLateAutorunChecked = false;
        }

        public void AddScore(int points, string reason)
        {
            lock (_scoreLock)
            {
                if (Score >= 100) return;

                Score += points;
                if (Score > 100) Score = 100;

                Reasons.Enqueue($"{reason} (+{points})");
            }
        }
    }
}