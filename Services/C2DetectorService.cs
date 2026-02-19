using CommandAndControll.Models;
using MyEventTracer;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using CommandAndControll.Utils;

namespace CommandAndControll.Services
{
    public class C2DetectorService
    {
        private ConcurrentDictionary<int, MonitoredProcess> _monitoringPids;
        private readonly WhiteListService _whiteListService;
        private readonly EventTracer _tracer;

        // Log fayllarim test uchun
        private const string FileActivity = "activity_log.txt";
        private const string FileMonitor = "monitoring_log.txt";
        private const string FileWhitelist = "whitelist_log.txt";

        private readonly object _logLock = new object();

        // Eventlar
        public event EventHandler<AlertEventArgs> OnAlert;
        public event EventHandler<TrafficEventArgs> OnTrafficDetected;

        public C2DetectorService()
        {
            _monitoringPids = new ConcurrentDictionary<int, MonitoredProcess>();
            _whiteListService = new WhiteListService();
            _tracer = EventTracer.Instance;

            LogTo(FileActivity, $"\n\n");
            LogTo(FileActivity, $"   SYSTEM STARTED: {DateTime.Now}");
            LogTo(FileActivity, $"\n\n");
        }

        public void Start()
        {
            _tracer.ProcessMonitor += OnProcessEvent;
            _tracer.NetworkIOMonitor += OnNetworkEvent;
            _tracer.Start(TraceModule.Process);
            _tracer.Start(TraceModule.NetworkIO);
            LogTo(FileActivity, "[SYSTEM] MyEventTracer ga ulandi");
        }

        public void Stop()
        {
            _tracer.ProcessMonitor -= OnProcessEvent;
            _tracer.NetworkIOMonitor -= OnNetworkEvent;
            LogTo(FileActivity, $"[SYSTEM] Monitoring to'xtadi: {DateTime.Now}");
        }

        private void OnProcessEvent(ProcessTraceData data)
        {
            if (!data.IsStart)
            {
                // Whitelistdan o'chirish
                if (_whiteListService.IsWhitelisted(data.ProcessId))
                {
                    _whiteListService.RemoveFromWhitelist(data.ProcessId);
                    LogTo(FileWhitelist, $"[REMOVE] PID: {data.ProcessId} (Process Exit)");
                }

                // Monitoringdan o'chirish
                if (_monitoringPids.TryRemove(data.ProcessId, out var removedProc))
                {
                    LogTo(FileMonitor, $"[STOP WATCH] PID: {data.ProcessId} Name: {removedProc.ProcessName} | Final Score: {removedProc.Score}");
                }
            }
        }

        
        private void OnNetworkEvent(NetworkIOTraceData data)
        {
            try
            {
                if (IsLocalAddress(data.RemoteAddress)) return;

                int pid = data.ProcessId;

                // PRIORITY 1 Blacklist check
                if (_whiteListService.IsBlacklistedIp(data.RemoteAddress))
                {
                    LogTo(FileActivity, $"[ BLACKLIST HIT ] PID: {pid} ({data.ProcessName}) connected to {data.RemoteAddress}");

                    TriggerAlert(pid, data.ProcessImagePath, 100, $"BLACKLISTED IP CONNECTION: {data.RemoteAddress}");

                    // Alert bergandan keyin uni boshqa chiqarmaslik kerak shunga whitelist ga qo'shib yuboraman
                    if (!_whiteListService.IsWhitelisted(pid))
                    {
                        _whiteListService.AddToWhitelist(pid);
                        LogTo(FileWhitelist, $"[ADD] PID: {pid} (Whitelisted after Blacklist Alert)");
                    }
                    return;
                }

                // PRIORITY 2 WHITELIST CHECK
                if (_whiteListService.IsWhitelisted(pid)) return;

                // PRIORITY 3 REGISTRATION (Yangi pid)
                if (!_monitoringPids.ContainsKey(pid))
                {
                    RegisterProcessIfNeeded(data);
                }

                // PRIORITY 4: ANALYSIS (Agar monitoringda bo'lsa)
                if (_monitoringPids.TryGetValue(pid, out var proc))
                {
                    AnalyzeTraffic(proc, data);

                    // Event yuborishim uchun
                    OnTrafficDetected?.Invoke(this, new TrafficEventArgs
                    {
                        Pid = pid,
                        CurrentScore = proc.Score,
                        IsSend = data.IsSend,
                        RemoteAddress = data.RemoteAddress,
                        RemotePort = data.RemotePort,
                        Size = data.Size,
                        ProcessPath = data.ProcessImagePath
                    });
                }
            }
            catch (Exception ex)
            {
                LogTo(FileActivity, $"[ERROR] OnNetworkEvent: {ex.Message}");
            }
        }

        // Ro'yxatga qo'shishimga (Score berishga)
        private void RegisterProcessIfNeeded(NetworkIOTraceData data)
        {
            string path = data.ProcessImagePath;
            if (string.IsNullOrEmpty(path) || !File.Exists(path)) return;

            // Signed -> Whitelist
            if (SystemUtils.IsSigned(path))
            {
                _whiteListService.AddToWhitelist(data.ProcessId);
                LogTo(FileWhitelist, $"[ADD] PID: {data.ProcessId} Name: {data.ProcessName} | Reason: Valid Signature");
                return;
            }

            // B) Unsigned -> Monitoring
            var newProc = new MonitoredProcess(data.ProcessId, path, data.ProcessName);
            string msg = $"[START WATCH] PID: {data.ProcessId} Path: {path} | Reason: Unsigned";
            LogTo(FileMonitor, msg);
            LogTo(FileActivity, msg);


            // 1. Unsigned: +25 ball qo'shdim
            AddScore(newProc, 20, "Unsigned Process Detected");

            // 2. Unusual Path: +20 (Desktop/Temp...)
            if (SystemUtils.IsUnusualPath(path))
            {
                newProc.IsInUnusualPath = true;
                AddScore(newProc, 20, "Running from Unusual Path");
            }

            // 3. Autorun Persistence: +30
            // (Agar boshlanishida registryda bor bo'lsa)
            if (SystemUtils.IsAutorun(data.ProcessName, path))
            {
                newProc.IsAutorun = true;
                AddScore(newProc, 30, "Persistence Found (Autorun)");
            }

            if (!newProc.IsPeChecked)
            {
                newProc.IsPeChecked = true;

                var imports = PeScanner.GetSuspiciousImports(path);

                if (imports.Count > 0)
                {
                    newProc.SuspiciousImports = imports;
                    EvaluatePeImports(newProc, imports);
                }
            }

            _monitoringPids.TryAdd(data.ProcessId, newProc);
            CheckForAlert(newProc);
        }


        private void CheckDeadIpConnection(MonitoredProcess proc, NetworkIOTraceData data)
        {
            string endpoint = $"{data.RemoteAddress}:{data.RemotePort}";

            if (data.IsSend)
            {
                if (!proc.UnansweredRequests.ContainsKey(endpoint))
                {
                    proc.UnansweredRequests[endpoint] = 0;
                }

                proc.UnansweredRequests[endpoint]++;

                if (proc.UnansweredRequests[endpoint] >= 10 && !proc.DeadIpsFlagged.Contains(endpoint))
                {
                    proc.DeadIpsFlagged.Add(endpoint);

                    AddScore(proc, 20, $"Attempts to connect to a dead IP:Port ({endpoint})");
                    LogTo(FileActivity, $"[DEAD IP DETECTED] PID: {proc.Pid} ({proc.ProcessName}) javobsiz manzilga ulanishga urinyapti: {endpoint}");
                }
            }
            else
            {
                if (proc.UnansweredRequests.ContainsKey(endpoint))
                {
                    proc.UnansweredRequests[endpoint] = 0;
                }
            }
        }

        // File header dan u chaqirgan shubxali api larni olishim uchun bu faqat unsigned va internetga chiqayotgan bo'lsa keyin ishlaydi
        private void EvaluatePeImports(MonitoredProcess proc, Dictionary<string, List<string>> imports)
        {
            int suspiciousApiCount = 0;
            int totalApiScore = 0;

            foreach (var dll in imports)
            {
                foreach (var api in dll.Value)
                {
                    suspiciousApiCount++;

                    int apiScore = 0;
                    string threatCategory = "Shubhali API ni chaqirmoqchi";
                    string apiLower = api.ToLower();

                    if (apiLower.Contains("remotethread") || apiLower.Contains("writeprocessmemory"))
                    {
                        apiScore = 10;
                        threatCategory = $"Process Injection qilsa bo'ladigan funksiyalarni chaqirdi";
                    }
                    else if (apiLower.Contains("hook") || apiLower.Contains("asynckey"))
                    {
                        apiScore = 8;
                        threatCategory = "Keylogger bo'lishi mumkin";
                    }
                    else if (apiLower.Contains("virtualalloc"))
                    {
                        apiScore = 3;
                        threatCategory = "Xotira ajratish uchun qo'shimcha api";
                    }
                    else if (apiLower.Contains("debugger"))
                    {
                        apiScore = 4;
                        threatCategory = "Anti-Analysis tekshiruvdan qochish bo'lishi mumkin";
                    }
                    else
                    {
                        apiScore = 3;
                        threatCategory = "Shifrlash uchun mo'ljallangan windows api larni chaqirdi";
                    }

                    totalApiScore += apiScore;

                    AddScore(proc, apiScore, $"{threatCategory} => API: {api} ({dll.Key})");
                }
            }

            LogTo(FileActivity, $"[PE SCAN] PID: {proc.Pid} da {suspiciousApiCount} ta xavfli API topildi. Toplangan jami ball: {totalApiScore}");
        }

        // Traffic ni tahlil qilishim uchun
        private void AnalyzeTraffic(MonitoredProcess proc, NetworkIOTraceData data)
        {
            proc.PacketsCount++;
            if (data.IsSend) proc.SendBytes += (ulong)data.Size;
            else proc.ReceivedBytes += (ulong)data.Size;

            string direction = data.IsSend ? "SEND" : "RECV";
            LogTo(FileMonitor, $"[TRAFFIC] PID: {proc.Pid} [Score: {proc.Score}] | {direction} => {data.RemoteAddress}:{data.RemotePort} | {data.Size} byte");

            CheckDeadIpConnection(proc, data);

            // Late autrun tekshirish uchun
            // Virus ishga tushgandan keyin o'zini registryga yozishi mumkin.
            // Buni aniqlash har 20-paketda qayta tekshirishim
            if (!proc.IsAutorun && proc.PacketsCount % 20 == 0)
            {
                if (SystemUtils.IsAutorun(proc.ProcessName, proc.FullPath))
                {
                    proc.IsAutorun = true;
                    AddScore(proc, 30, "Persistence Detected (Late Check)"); // +30 ball
                    LogTo(FileMonitor, $"[LATE CHECK] PID: {proc.Pid} found in Autorun!");
                }
            }

            // Unusual Port Check +20
            if (!proc.UsedUnusualPort)
            {
                if (data.RemotePort != 80 && data.RemotePort != 443 && data.RemotePort != 8080)
                {
                    proc.UsedUnusualPort = true;
                    AddScore(proc, 20, $"Unusual Remote Port: {data.RemotePort}");
                }
            }

            // Ratio check uchun faqat ma'lumot jo'nativorsa send qilaverda 90%+ 
            if (proc.RatioPenaltyCount < 5 && proc.PacketsCount % 10 == 0)
            {
                double total = proc.SendBytes + proc.ReceivedBytes;
                if (total > 0)
                {
                    double sendRatio = (double)proc.SendBytes / total;
                    if (sendRatio > 0.90) // 90% dan ko'p Send bo'ldi
                    {
                        proc.RatioPenaltyCount++;
                        AddScore(proc, 5, $"Suspicious Upload Ratio ({proc.RatioPenaltyCount}/5)");
                    }
                }
            }

            // Volume Check (>5GB) +50 ball
            if (proc.SendBytes > 5368709120 && !proc.Reasons.Any(r => r.Contains("Massive")))
            {
                AddScore(proc, 50, "Massive Data Exfiltration (>5GB)");
            }

            CheckForAlert(proc);
        }

        private void AddScore(MonitoredProcess proc, int points, string reason)
        {
            proc.AddScore(points, reason);
            if (proc.Score > 100) proc.Score = 100;
            LogTo(FileMonitor, $"   => [SCORE UP] PID: {proc.Pid} | +{points} => Total: {proc.Score} | Reason: {reason}");
        }

        private void CheckForAlert(MonitoredProcess proc)
        {
            if (proc.Score >= 80 && !proc.AlertTriggered)
            {
                proc.AlertTriggered = true;
                string alertMsg = $"[ ALERT ] PID: {proc.Pid} => {proc.Score} ball yig'di";
                LogTo(FileActivity, alertMsg);
                LogTo(FileMonitor, alertMsg);

                LogTo(FileActivity, alertMsg);

                TriggerAlert(proc.Pid, proc.FullPath, proc.Score, string.Join(", ", proc.Reasons));
            }
        }

        private void TriggerAlert(int pid, string path, int score, string reasons)
        {
            OnAlert?.Invoke(this, new AlertEventArgs
            {
                Process = _monitoringPids.ContainsKey(pid) ? _monitoringPids[pid] : new MonitoredProcess(pid, path, "Unknown"),
                Message = $"PID: {pid} | Score: {score} | {reasons}"
            });
        }

        // Thread-Safe File Writer
        private void LogTo(string fileName, string message)
        {
            lock (_logLock)
            {
                try
                {
                    string logLine = $"{DateTime.Now:HH:mm:ss.fff} {message}{Environment.NewLine}";
                    File.AppendAllText(fileName, logLine);
                }
                catch {  }
            }
        }

        //public bool IsLocalAddress(string ip)
        //{
        //    if (string.IsNullOrEmpty(ip)) return false;
        //    return ip == "127.0.0.1" || ip == "::1" ||
        //           ip.StartsWith("192.168.") ||
        //           ip.StartsWith("10.") ||
        //           ip.StartsWith("172.16.");
        //}

        public bool IsLocalAddress(string ip)
        {
            if (string.IsNullOrEmpty(ip)) return false;

            return ip == "127.0.0.1" || ip == "::1" || ip == "localhost";
        }

    }
}