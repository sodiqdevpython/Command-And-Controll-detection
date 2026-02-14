namespace CommandAndControll.Models
{
    public enum ScanResult
    {
        /// <summary>
        /// Hali tekshirilmagan yoki noma'lum.
        /// </summary>
        Unknown,

        /// <summary>
        /// Toza Signed yoki ishonchli
        /// </summary>
        Clean,

        /// <summary>
        /// Whitelistda bor tekshirish shart emas
        /// </summary>
        Whitelisted,

        /// <summary>
        /// Monitoringda lekin hali aniq emas virus ekanligi
        /// </summary>
        Suspicious,

        /// <summary>
        /// Xavfli (Ball > 80 yoki Blacklist IP).
        /// </summary>
        Malicious
    }
}