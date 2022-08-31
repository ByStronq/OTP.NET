namespace OTP.NET.Concrete
{
    internal static class KeyUtilities
    {
        internal static void Destroy(byte[] sensitiveData)
        {
            if (sensitiveData is null) throw new ArgumentNullException(nameof(sensitiveData));

            new Random().NextBytes(sensitiveData);
        }

        internal static byte[] GetBigEndianBytes(long input)
        {
            var data = BitConverter.GetBytes(input);

            Array.Reverse(data);

            return data;
        }

        internal static byte[] GetBigEndianBytes(int input)
        {
            var data = BitConverter.GetBytes(input);

            Array.Reverse(data);

            return data;
        }
    }
}
