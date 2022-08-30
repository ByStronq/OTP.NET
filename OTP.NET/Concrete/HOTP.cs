using OTP.NET.Abstract;

namespace OTP.NET.Concrete
{
    public class HOTP : OTPBase
    {
        private readonly int _hotpSize;

        public HOTP(byte[] secretKey, OTPHashMode mode = OTPHashMode.Sha1, int hotpSize = 6) : base(secretKey, mode)
        {
            VerifyParameters(hotpSize);

            _hotpSize = hotpSize;
        }

        public HOTP(IKeyProvider key, OTPHashMode mode = OTPHashMode.Sha1, int hotpSize = 6) : base(key, mode)
        {
            VerifyParameters(hotpSize);

            _hotpSize = hotpSize;
        }

        private static void VerifyParameters(int hotpSize)
        {
            if (!(hotpSize >= 6)) throw new ArgumentOutOfRangeException(nameof(hotpSize));

            if (!(hotpSize <= 8)) throw new ArgumentOutOfRangeException(nameof(hotpSize));
        }

        public string ComputeHOTP(long counter) => Compute(counter, _hashMode);

        public bool VerifyHotp(string hotp, long counter)
        {
            if (hotp == ComputeHOTP(counter)) return true;

            return false;
        }

        protected override string Compute(long counter, OTPHashMode mode)
        {
            var data = KeyUtilities.GetBigEndianBytes(counter);

            var otp = CalculateOtp(data, mode);

            return Digits(otp, _hotpSize);
        }
    }
}
