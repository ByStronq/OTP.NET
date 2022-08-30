using OTP.NET.Concrete;

namespace OTP.NET.Abstract
{
    public abstract class OTPBase
    {
        protected readonly IKeyProvider _secretKey;
        protected readonly OTPHashMode _hashMode;

        public OTPBase(byte[] secretKey, OTPHashMode mode)
        {
            if (secretKey is null) throw new ArgumentNullException(nameof(secretKey));

            if (!(secretKey.Length > 0)) throw new ArgumentException("secretKey empty");

            _secretKey = new InMemoryKey(secretKey);
            _hashMode = mode;
        }

        public OTPBase(IKeyProvider key, OTPHashMode mode)
        {
            if (key is null) throw new ArgumentNullException(nameof(key));

            _secretKey = key;
            _hashMode = mode;
        }

        protected abstract string Compute(long counter, OTPHashMode mode);

        protected internal long CalculateOtp(byte[] data, OTPHashMode mode)
        {
            byte[] hmacComputedHash = _secretKey.ComputeHmac(mode, data);

            int offset = hmacComputedHash[hmacComputedHash.Length - 1] & 0x0F;

            return (hmacComputedHash[offset] & 0x7f) << 24
                | (hmacComputedHash[offset + 1] & 0xff) << 16
                | (hmacComputedHash[offset + 2] & 0xff) << 8
                | (hmacComputedHash[offset + 3] & 0xff) % 1000000;
        }

        protected internal static string Digits(long input, int digitCount)
        {
            var truncatedValue = (int) input % (int) Math.Pow(10, digitCount);

            return truncatedValue.ToString().PadLeft(digitCount, '0');
        }

        protected bool Verify(long initialStep, string valueToVerify, out long matchedStep, VerificationWindow window)
        {
            window ??= new VerificationWindow();

            foreach(var frame in window.ValidationCandidates(initialStep))
            {
                var comparisonValue = Compute(frame, _hashMode);

                if (ValuesEqual(comparisonValue, valueToVerify))
                {
                    matchedStep = frame;

                    return true;
                }
            }

            matchedStep = 0;

            return false;
        }

        private static bool ValuesEqual(string a, string b)
        {
            if (a.Length != b.Length) return false;

            var result = 0;

            for (int i = 0; i < a.Length; i++) result |= a[i] ^ b[i];

            return result == 0;
        }
    }
}
