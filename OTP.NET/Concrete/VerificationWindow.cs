namespace OTP.NET.Concrete
{
    public class VerificationWindow
    {
        private readonly int _previous;
        private readonly int _future;

        public VerificationWindow(int previous = 0, int future = 0)
        {
            _previous = previous;
            _future = future;
        }

        public IEnumerable<long> ValidationCandidates(long initialFrame)
        {
            yield return initialFrame;

            for (int i = 1; i <= _previous; i++)
            {
                var val = initialFrame - i;

                if(val < 0) break;

                yield return val;
            }

            for (int i = 1; i <= _future; i++) yield return initialFrame + i;
        }

        public static readonly VerificationWindow RfcSpecifiedNetworkDelay = new(previous: 1, future: 1);
    }
}
