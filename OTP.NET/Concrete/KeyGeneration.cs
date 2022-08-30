using OTP.NET.Abstract;
using System.Security.Cryptography;

namespace OTP.NET.Concrete
{
    public static class KeyGeneration
    {
        public static byte[] GenerateRandomKey(int length)
        {
            byte[] key = new byte[length];

            using var rnd = RandomNumberGenerator.Create();

            rnd.GetBytes(key);

            return key;
        }

        public static byte[] GenerateRandomKey(OTPHashMode mode = OTPHashMode.Sha1) => GenerateRandomKey(LengthForMode(mode));

        public static byte[] DeriveKeyFromMaster(IKeyProvider masterKey, byte[] publicIdentifier, OTPHashMode mode = OTPHashMode.Sha1)
        {
            if (masterKey is null) throw new ArgumentNullException(nameof(masterKey));

            return masterKey.ComputeHmac(mode, publicIdentifier);
        }

        public static byte[] DeriveKeyFromMaster(IKeyProvider masterKey, int serialNumber, OTPHashMode mode = OTPHashMode.Sha1)
        {
            return DeriveKeyFromMaster(masterKey, KeyUtilities.GetBigEndianBytes(serialNumber), mode);
        }

        private static HashAlgorithm GetHashAlgorithmForMode(OTPHashMode mode) => mode switch
        {
            OTPHashMode.Sha256 => SHA256.Create(),
            OTPHashMode.Sha512 => SHA512.Create(),
            _ => SHA1.Create()
        };

        private static int LengthForMode(OTPHashMode mode) => mode switch
        {
            OTPHashMode.Sha256 => 32,
            OTPHashMode.Sha512 => 64,
            _ => 20
        };
    }
}
