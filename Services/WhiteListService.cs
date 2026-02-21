using System;
using System.Collections.Concurrent; // Thread-safe collections ga kerak bo'ldi bu
using System.Collections.Generic;
using System.IO;

namespace CommandAndControl.Services
{
    public class WhiteListService
    {
        // Thread-safe PID ro'yxati (whitelist pids)
        private ConcurrentDictionary<int, byte> _whitelistedPids = new ConcurrentDictionary<int, byte>();

        // Qora ro'yxatdagi IP manzillar
        private HashSet<string> _blacklistedIps = new HashSet<string>();

        private const string BlacklistFileName = "blacklist.txt";

        public WhiteListService()
        {
            LoadBlacklist();
        }

        /// <summary>
        /// blacklist.txt faylidan IP larni yuklashim uchun
        /// </summary>
        private void LoadBlacklist()
        {
            try
            {
                if (File.Exists(BlacklistFileName))
                {
                    var lines = File.ReadAllLines(BlacklistFileName);
                    foreach (var line in lines)
                    {
                        if (!string.IsNullOrWhiteSpace(line) && !line.StartsWith("#"))
                        {
                            _blacklistedIps.Add(line.Trim());
                        }
                    }
                    //Console.WriteLine($"{_blacklistedIps.Count}");
                }
                else
                {
                    // Fayl yo'q bo'lsa create qildim
                    File.WriteAllText(BlacklistFileName, "# Shubhali ip lar shu yerda turadi");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[ERROR] Could not load blacklist: {ex.Message}");
            }
        }

        /// <summary>
        /// PID Whitelistda bormi qarashimga
        /// </summary>
        public bool IsWhitelisted(int pid)
        {
            return _whitelistedPids.ContainsKey(pid);
        }

        /// <summary>
        /// PID ni Whitelistga qo'shish signed bo'lsagina
        /// </summary>
        public void AddToWhitelist(int pid)
        {
            _whitelistedPids.TryAdd(pid, 0);
        }

        /// <summary>
        /// Process yopilganda Whitelistdan o'chirish xotirani tozalashim uchun
        /// </summary>
        public void RemoveFromWhitelist(int pid)
        {
            byte dummy;
            _whitelistedPids.TryRemove(pid, out dummy);
        }

        /// <summary>
        /// IP Blacklistda bormi?
        /// </summary>
        public bool IsBlacklistedIp(string ip)
        {
            if (string.IsNullOrEmpty(ip)) return false;
            return _blacklistedIps.Contains(ip);
        }

        public bool IsSystemProcess(string imagePath)
        {
            if (string.IsNullOrEmpty(imagePath)) return false;

            string lowerPath = imagePath.ToLower();
            return lowerPath.Contains(@"\windows\system32\") || lowerPath.Contains(@"\windows\syswow64\");
        }
    }
}