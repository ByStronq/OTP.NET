using OTP.NET.Abstract;

namespace OTP.NET.Concrete
{
    public class TOTP : OTPBase
    {
        const long unixEpochTicks = 621355968000000000L;
        const long ticksToSeconds = 10000000L;

        private readonly int _step;
        private readonly int _totpSize;
        private readonly TimeCorrection _correctedTime;

        public TOTP(byte[] secretKey, int step = 30, OTPHashMode mode = OTPHashMode.Sha1, int totpSize = 6, TimeCorrection? timeCorrection = null) : base(secretKey, mode)
        {
            VerifyParameters(step, totpSize);

            _step = step;
            _totpSize = totpSize;

            _correctedTime = timeCorrection ?? TimeCorrection.UncorrectedInstance;
        }

        public TOTP(IKeyProvider key, int step = 30, OTPHashMode mode = OTPHashMode.Sha1, int totpSize = 6, TimeCorrection? timeCorrection = null) : base(key, mode)
        {
            VerifyParameters(step, totpSize);

            _step = step;
            _totpSize = totpSize;

            _correctedTime = timeCorrection ?? TimeCorrection.UncorrectedInstance;
        }

        private static void VerifyParameters(int step, int totpSize)
        {
            if (!(step > 0)) throw new ArgumentOutOfRangeException(nameof(step));

            if (!(totpSize > 0)) throw new ArgumentOutOfRangeException(nameof(totpSize));

            if (!(totpSize <= 10)) throw new ArgumentOutOfRangeException(nameof(totpSize));
        }

        public string ComputeTotp(DateTime timestamp) => ComputeTotpFromSpecificTime(_correctedTime.GetCorrectedTime(timestamp));

        public string ComputeTotp() => ComputeTotpFromSpecificTime(_correctedTime.CorrectedUtcNow);

        private string ComputeTotpFromSpecificTime(DateTime timestamp)
        {
            var window = CalculateTimeStepFromTimestamp(timestamp);

            return Compute(window, _hashMode);
        }

        public bool VerifyTotp(string totp, out long timeStepMatched, VerificationWindow? window = null) => VerifyTotpForSpecificTime(_correctedTime.CorrectedUtcNow, totp, window, out timeStepMatched);

        public bool VerifyTotp(DateTime timestamp, string totp, out long timeStepMatched, VerificationWindow? window = null) => VerifyTotpForSpecificTime(_correctedTime.GetCorrectedTime(timestamp), totp, window, out timeStepMatched);

        private bool VerifyTotpForSpecificTime(DateTime timestamp, string totp, VerificationWindow window, out long timeStepMatched)
        {
            var initialStep = CalculateTimeStepFromTimestamp(timestamp);

            return Verify(initialStep, totp, out timeStepMatched, window);
        }

        private long CalculateTimeStepFromTimestamp(DateTime timestamp)
        {
            var unixTimestamp = (timestamp.Ticks - unixEpochTicks) / ticksToSeconds;

            var window = unixTimestamp / _step;

            return window;
        }

        public int RemainingSeconds() => RemainingSecondsForSpecificTime(_correctedTime.CorrectedUtcNow);

        public int RemainingSeconds(DateTime timestamp) => RemainingSecondsForSpecificTime(_correctedTime.GetCorrectedTime(timestamp));

        private int RemainingSecondsForSpecificTime(DateTime timestamp) => _step - (int) ((timestamp.Ticks - unixEpochTicks) / ticksToSeconds % _step);

        protected override string Compute(long counter, OTPHashMode mode)
        {
            var data = KeyUtilities.GetBigEndianBytes(counter);

            var otp = CalculateOtp(data, mode);

            return Digits(otp, _totpSize);
        }
    }
}
