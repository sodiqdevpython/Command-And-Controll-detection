using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace CommandAndControl.Utils
{
    public static class PeScanner
    {
        // Shubhali api lar manzili bilan
        private static readonly Dictionary<string, string> SuspiciousApis = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            { "VirtualAlloc", "kernel32.dll" },
            { "VirtualAllocEx", "kernel32.dll" },
            { "WriteProcessMemory", "kernel32.dll" },
            { "CreateRemoteThread", "kernel32.dll" },
            { "IsDebuggerPresent", "kernel32.dll" },
            { "CheckRemoteDebuggerPresent", "kernel32.dll" },
            { "Sleep", "kernel32.dll" },
            { "SetWindowsHookExA", "user32.dll" },
            { "SetWindowsHookExW", "user32.dll" },
            { "GetAsyncKeyState", "user32.dll" },
            { "CryptAcquireContextA", "advapi32.dll" },
            { "CryptEncrypt", "advapi32.dll" },

            { "GetDC", "user32.dll" },                // Ekran yoki oyna kontekstini olish
            { "GetWindowDC", "user32.dll" },          // Butun window context ni olish
            { "CreateCompatibleDC", "gdi32.dll" },    // Xotirada rasm uchun virtual joy yaratish
            { "CreateCompatibleBitmap", "gdi32.dll" },// Rasm piksellari uchun xotira ajratish
            { "SelectObject", "gdi32.dll" },          // BitMapni kontekstga bog'lash
            { "BitBlt", "gdi32.dll" },                // Piksellarni copy qilish uchun
            { "StretchBlt", "gdi32.dll" },            // Rasmni o'lchamini o'zgartirib nusxalash
            { "PrintWindow", "user32.dll" },          // Ma'lum bir oynani rasmga olish
        };

        public static Dictionary<string, List<string>> GetSuspiciousImports(string filePath)
        {
            var foundImports = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);

            try
            {
                FileInfo fileInfo = new FileInfo(filePath);
                if (!fileInfo.Exists || fileInfo.Length < 0x40) return foundImports;

                long fileLength = fileInfo.Length;

                using (FileStream fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                using (BinaryReader br = new BinaryReader(fs))
                {
                    if (br.ReadUInt16() != 0x5A4D) return foundImports;

                    fs.Seek(0x3C, SeekOrigin.Begin);
                    uint peOffset = br.ReadUInt32();
                    if (peOffset == 0 || peOffset + 24 > fileLength) return foundImports;

                    fs.Seek(peOffset, SeekOrigin.Begin);
                    if (br.ReadUInt32() != 0x00004550) return foundImports;

                    br.ReadUInt16();
                    ushort numberOfSections = br.ReadUInt16();
                    fs.Seek(12, SeekOrigin.Current);
                    ushort sizeOfOptionalHeader = br.ReadUInt16();
                    fs.Seek(2, SeekOrigin.Current);

                    long optionalHeaderOffset = fs.Position;
                    if (optionalHeaderOffset + sizeOfOptionalHeader > fileLength) return foundImports;

                    ushort magic = br.ReadUInt16();
                    bool is64Bit = (magic == 0x20B);

                    long importDirRvaOffset = optionalHeaderOffset + (is64Bit ? 120 : 104);
                    if (importDirRvaOffset + 8 > fileLength) return foundImports;

                    fs.Seek(importDirRvaOffset, SeekOrigin.Begin);
                    uint importRva = br.ReadUInt32();

                    if (importRva == 0) return foundImports;

                    long sectionHeadersOffset = optionalHeaderOffset + sizeOfOptionalHeader;

                    Func<uint, uint> RvaToOffset = (rva) =>
                    {
                        long currentPos = fs.Position;
                        for (int i = 0; i < numberOfSections; i++)
                        {
                            long sectionOffset = sectionHeadersOffset + (i * 40);
                            if (sectionOffset + 40 > fileLength) break;

                            fs.Seek(sectionOffset + 8, SeekOrigin.Begin);
                            uint virtualSize = br.ReadUInt32();
                            uint virtualAddress = br.ReadUInt32();
                            uint sizeOfRawData = br.ReadUInt32();
                            uint pointerToRawData = br.ReadUInt32();

                            uint actualSize = Math.Max(virtualSize, sizeOfRawData);
                            if (rva >= virtualAddress && rva < virtualAddress + actualSize)
                            {
                                fs.Seek(currentPos, SeekOrigin.Begin);
                                return rva - virtualAddress + pointerToRawData;
                            }
                        }
                        fs.Seek(currentPos, SeekOrigin.Begin);
                        return 0;
                    };

                    uint importOffset = RvaToOffset(importRva);
                    if (importOffset == 0 || importOffset >= fileLength) return foundImports;

                    uint currentDescriptorOffset = importOffset;
                    int maxDlls = 500;
                    int dllCount = 0;

                    while (dllCount < maxDlls && currentDescriptorOffset + 20 <= fileLength)
                    {
                        fs.Seek(currentDescriptorOffset, SeekOrigin.Begin);
                        uint originalFirstThunk = br.ReadUInt32();
                        br.ReadUInt32();
                        br.ReadUInt32();
                        uint nameRva = br.ReadUInt32();
                        uint firstThunk = br.ReadUInt32();

                        if (nameRva == 0) break;

                        uint nameOffset = RvaToOffset(nameRva);
                        if (nameOffset == 0 || nameOffset >= fileLength) break;

                        fs.Seek(nameOffset, SeekOrigin.Begin);
                        string dllName = ReadStringSafe(fs, fileLength, 128);

                        uint thunkRva = (originalFirstThunk != 0) ? originalFirstThunk : firstThunk;
                        uint thunkOffset = RvaToOffset(thunkRva);
                        if (thunkOffset == 0 || thunkOffset >= fileLength) break;

                        uint thunkPos = thunkOffset;
                        int maxFuncs = 5000;
                        int funcCount = 0;

                        while (funcCount < maxFuncs && thunkPos + (is64Bit ? 8u : 4u) <= fileLength)
                        {
                            fs.Seek(thunkPos, SeekOrigin.Begin);
                            ulong thunkData = is64Bit ? br.ReadUInt64() : br.ReadUInt32();

                            if (thunkData == 0) break;

                            ulong ordinalFlag = is64Bit ? 0x8000000000000000 : 0x80000000;

                            if ((thunkData & ordinalFlag) == 0)
                            {
                                uint funcNameRva = (uint)(thunkData & 0x7FFFFFFF);
                                uint funcNameOffset = RvaToOffset(funcNameRva);

                                if (funcNameOffset != 0 && funcNameOffset + 2 < fileLength)
                                {
                                    fs.Seek(funcNameOffset + 2, SeekOrigin.Begin);
                                    string funcName = ReadStringSafe(fs, fileLength, 256);

                                    if (SuspiciousApis.TryGetValue(funcName, out string expectedDll))
                                    {
                                        if (dllName.StartsWith(expectedDll.Replace(".dll", ""), StringComparison.OrdinalIgnoreCase))
                                        {
                                            if (!foundImports.ContainsKey(dllName))
                                            {
                                                foundImports[dllName] = new List<string>();
                                            }
                                            foundImports[dllName].Add(funcName);
                                        }
                                    }
                                }
                            }

                            thunkPos += is64Bit ? 8u : 4u;
                            funcCount++;
                        }

                        currentDescriptorOffset += 20;
                        dllCount++;
                    }
                }
            }
            catch { }

            return foundImports;
        }

        private static string ReadStringSafe(FileStream fs, long fileLength, int maxLength)
        {
            List<byte> bytes = new List<byte>();
            int b;
            int count = 0;
            while (fs.Position < fileLength && count < maxLength)
            {
                b = fs.ReadByte();
                if (b == 0 || b == -1) break;
                bytes.Add((byte)b);
                count++;
            }
            return Encoding.ASCII.GetString(bytes.ToArray());
        }
    }
}