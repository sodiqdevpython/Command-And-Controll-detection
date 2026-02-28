using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace CommandAndControl.Services
{
    public static class SystemUtils
    {
        [DllImport("wintrust.dll", SetLastError = true)]
        private static extern bool CryptCATAdminAcquireContext(out IntPtr phCatAdmin, IntPtr pgSubsystem, int dwFlags);

        [DllImport("wintrust.dll", SetLastError = true)]
        private static extern bool CryptCATAdminCalcHashFromFileHandle(SafeFileHandle hFile, ref int pcbHash, byte[] pbHash, int dwFlags);

        [DllImport("wintrust.dll", SetLastError = true)]
        private static extern IntPtr CryptCATAdminEnumCatalogFromHash(IntPtr hCatAdmin, byte[] pbHash, int cbHash, int dwFlags, ref IntPtr phPrevCatInfo);

        [DllImport("wintrust.dll", SetLastError = true)]
        private static extern bool CryptCATAdminReleaseCatalogContext(IntPtr hCatAdmin, IntPtr hCatInfo, int dwFlags);

        [DllImport("wintrust.dll", SetLastError = true)]
        private static extern bool CryptCATAdminReleaseContext(IntPtr hCatAdmin, int dwFlags);

        // Digital sign tekshirishim uchun
        public static bool IsSigned(string filePath)
        {
            if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath)) return false;

            if (HasEmbeddedSignature(filePath)) return true;

            return HasCatalogSignature(filePath);
        }

        private static bool HasEmbeddedSignature(string filePath)
        {
            try
            {
                var cert = X509Certificate.CreateFromSignedFile(filePath);
                return cert != null;
            }
            catch
            {
                return false;
            }
        }

        private static bool HasCatalogSignature(string filePath)
        {
            IntPtr hCatAdmin = IntPtr.Zero;
            IntPtr hCatInfo = IntPtr.Zero;

            try
            {
                if (!CryptCATAdminAcquireContext(out hCatAdmin, IntPtr.Zero, 0))
                    return false;

                using (FileStream fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                {
                    int hashSize = 0;
                    CryptCATAdminCalcHashFromFileHandle(fs.SafeFileHandle, ref hashSize, null, 0);
                    if (hashSize == 0) return false;
                    byte[] hash = new byte[hashSize];
                    if (!CryptCATAdminCalcHashFromFileHandle(fs.SafeFileHandle, ref hashSize, hash, 0))
                        return false;

                    IntPtr hPrevCatInfo = IntPtr.Zero;
                    hCatInfo = CryptCATAdminEnumCatalogFromHash(hCatAdmin, hash, hashSize, 0, ref hPrevCatInfo);

                    return hCatInfo != IntPtr.Zero;
                }
            }
            catch
            {
                return false;
            }
            finally
            {
                if (hCatInfo != IntPtr.Zero)
                    CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
                if (hCatAdmin != IntPtr.Zero)
                    CryptCATAdminReleaseContext(hCatAdmin, 0);
            }
        }

        public static bool IsTrustedMicrosoftPath(string filePath)
        {
            if (string.IsNullOrEmpty(filePath)) return false;

            string lowerPath = filePath.ToLowerInvariant();

            return lowerPath.Contains(@"\program files\windowsapps\");
        }

        // Unusual folderlar Desktop ga ham faylni kiritish va ishga tushirish osonligi uchun uniyam qo'shdim
        public static bool IsUnusualPath(string filePath)
        {
            if (string.IsNullOrEmpty(filePath)) return false;

            // Faqat bitta allocation qilinadi
            string lowerPath = filePath.ToLowerInvariant();

            // Ikki tomoniga '\' qo'shib tekshiramiz. Tez va aniq!
            return lowerPath.Contains("\\appdata\\local\\temp\\") ||
                   lowerPath.Contains("\\downloads\\") ||
                   lowerPath.Contains("\\desktop\\") ||
                   lowerPath.Contains("\\$recycle.bin\\") ||
                   lowerPath.Contains("\\programdata\\") ||
                   lowerPath.Contains("\\users\\public\\");
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