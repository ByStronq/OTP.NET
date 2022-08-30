namespace OTP.NET.Concrete
{
    public class TimeCorrection
    {
        public static readonly TimeCorrection UncorrectedInstance = new();

        private readonly TimeSpan _timeCorrectionFactor;

        public DateTime CorrectedUtcNow => GetCorrectedTime(DateTime.UtcNow);

        public TimeSpan CorrectionFactor => _timeCorrectionFactor;

        private TimeCorrection() => _timeCorrectionFactor = TimeSpan.FromSeconds(0);

        public TimeCorrection(DateTime correctUtc) => _timeCorrectionFactor = DateTime.UtcNow - correctUtc;

        public TimeCorrection(DateTime correctTime, DateTime referenceTime) => _timeCorrectionFactor = referenceTime - correctTime;

        public DateTime GetCorrectedTime(DateTime referenceTime) => referenceTime - _timeCorrectionFactor;
    }
}
