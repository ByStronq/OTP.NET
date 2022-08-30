using OTP.NET.Abstract;
using System.Security.Cryptography;

namespace OTP.NET.Concrete
{
    public class InMemoryKey : IKeyProvider
    {
        private readonly object _stateSync = new();
        private readonly byte[] _keyData;
        private readonly int _keyLength;

        public InMemoryKey(byte[] key)
        {
            if (key is null) throw new ArgumentNullException(nameof(key));

            if (!(key.Length > 0)) throw new ArgumentException("The key must not be empty");

            _keyLength = key.Length;

            int paddedKeyLength = (int) Math.Ceiling((decimal) key.Length / 16) * 16;

            _keyData = new byte[paddedKeyLength];

            Array.Copy(key, _keyData, key.Length);
        }

        internal byte[] GetCopyOfKey()
        {
            var plainKey = new byte[_keyLength];

            lock (_stateSync) Array.Copy(_keyData, plainKey, _keyLength);

            return plainKey;
        }

        public byte[] ComputeHmac(OTPHashMode mode, byte[] data)
        {
            byte[]? hashedValue = null;

            using var hmac = CreateHmacHash(mode);

            byte[] key = this.GetCopyOfKey();

            try
            {
                hmac.Key = key;
                hashedValue = hmac.ComputeHash(data);
            }
            finally
            {
                KeyUtilities.Destroy(key);
            }

            return hashedValue;
        }

        private static HMAC CreateHmacHash(OTPHashMode otpHashMode) => otpHashMode switch
        {
            OTPHashMode.Sha256 => new HMACSHA256(),
            OTPHashMode.Sha512 => new HMACSHA512(),
            _ => new HMACSHA1()
        };
    }
}
