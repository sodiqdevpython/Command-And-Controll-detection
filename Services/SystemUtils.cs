using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Win32;

namespace CommandAndControll.Services
{
    public static class SystemUtils
    {
        // Digital sign tekshirishim uchun
        public static bool IsSigned(string filePath)
        {
            try
            {
                if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath)) return false;

                var cert = X509Certificate.CreateFromSignedFile(filePath);
                return cert != null;
            }
            catch
            {
                return false; // Xatolik bo'lsa yoki imzo yo'q bo'lsa false deyman
            }
        }

        // Unusual folderlar Desktop ga ham faylni kiritish va ishga tushirish osonligi uchun uniyam qo'shdim
        public static bool IsUnusualPath(string filePath)
        {
            if (string.IsNullOrEmpty(filePath)) return false;
            string lowerPath = filePath.ToLower();

            // Viruslar eng ko'p yashirinadigan joylar:
            return lowerPath.Contains("\\appdata\\local\\temp") || // Temp
                   lowerPath.Contains("\\downloads") || // Downloads
                   lowerPath.Contains("\\desktop") ||  // Desktop (YANGI)
                   lowerPath.Contains("\\recycle.bin") ||
                   lowerPath.Contains("\\programdata") || // ProgramData
                   lowerPath.Contains("\\users\\public"); // Public user papkasi
        }

        // 3. Autorun da borligini tekshirishim uchun
        public static bool IsAutorun(string processName, string fullPath)
        {
            try
            {
                // Registry: Standard Run Keys
                if (CheckReg(Registry.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Run", processName, fullPath)) return true;
                if (CheckReg(Registry.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\Run", processName, fullPath)) return true;

                // Registry: RunOnce
                if (CheckReg(Registry.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\RunOnce", processName, fullPath)) return true;
                if (CheckReg(Registry.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\RunOnce", processName, fullPath)) return true;

                // Registry: Policies 
                if (CheckReg(Registry.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run", processName, fullPath)) return true;
                if (CheckReg(Registry.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run", processName, fullPath)) return true;

                // Windows Services (Servis sifatida)
                if (CheckServices(processName, fullPath)) return true;

                // Startup Folder
                if (CheckStartupFolder(Environment.GetFolderPath(Environment.SpecialFolder.Startup), processName)) return true;
                if (CheckStartupFolder(Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup), processName)) return true;
            }
            catch { }

            return false;
        }

        private static bool CheckReg(RegistryKey root, string keyPath, string name, string fullPath)
        {
            try
            {
                using (var key = root.OpenSubKey(keyPath))
                {
                    if (key != null)
                    {
                        foreach (var valueName in key.GetValueNames())
                        {
                            string value = key.GetValue(valueName)?.ToString().ToLower() ?? "";

                            if (value.Contains(name.ToLower()) || value.Contains(fullPath.ToLower()))
                                return true;
                        }
                    }
                }
            }
            catch { }
            return false;
        }

        private static bool CheckServices(string name, string fullPath)
        {
            try
            {
                using (var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services"))
                {
                    if (key != null)
                    {
                        foreach (var subKeyName in key.GetSubKeyNames())
                        {
                            using (var serviceKey = key.OpenSubKey(subKeyName))
                            {
                                var imagePath = serviceKey?.GetValue("ImagePath")?.ToString().ToLower();
                                if (imagePath != null && (imagePath.Contains(name.ToLower()) || imagePath.Contains(fullPath.ToLower())))
                                {
                                    return true;
                                }
                            }
                        }
                    }
                }
            }
            catch { }
            return false;
        }

        private static bool CheckStartupFolder(string folderPath, string name)
        {
            try
            {
                if (Directory.Exists(folderPath))
                {
                    var files = Directory.GetFiles(folderPath, "*.lnk");
                    foreach (var file in files)
                    {
                        if (Path.GetFileNameWithoutExtension(file).Equals(Path.GetFileNameWithoutExtension(name), StringComparison.OrdinalIgnoreCase))
                            return true;
                    }

                    var exes = Directory.GetFiles(folderPath, "*.exe");
                    foreach (var file in exes)
                    {
                        if (Path.GetFileName(file).Equals(name, StringComparison.OrdinalIgnoreCase))
                            return true;
                    }
                }
            }
            catch { }
            return false;
        }
    }
}