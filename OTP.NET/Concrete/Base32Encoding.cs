namespace OTP.NET.Concrete
{
    public static class Base32Encoding
    {
        public static byte[] ToBytes(string input)
        {
            if (string.IsNullOrWhiteSpace(input)) throw new ArgumentNullException(nameof(input));

            input = input.TrimEnd('=');

            int byteCount = input.Length * 5 / 8, arrayIndex = 0;
            byte curByte = 0, bitsRemaining = 8;

            byte[] returnArray = new byte[byteCount];

            foreach (char c in input)
            {
                int cValue = CharToValue(c), mask;

                if (bitsRemaining > 5)
                {
                    mask = cValue << (bitsRemaining - 5);
                    curByte = (byte) (curByte | mask);
                    bitsRemaining -= 5;
                }
                else
                {
                    mask = cValue >> (5 - bitsRemaining);
                    curByte = (byte) (curByte | mask);
                    returnArray[arrayIndex++] = curByte;
                    curByte = (byte) (cValue << (3 + bitsRemaining));
                    bitsRemaining += 3;
                }
            }

            if (arrayIndex != byteCount) returnArray[arrayIndex] = curByte;

            return returnArray;
        }

        public static string ToString(byte[] input)
        {
            if (input is null || input.Length == 0) throw new ArgumentNullException(nameof(input));

            int charCount = (int) Math.Ceiling(input.Length / 5d) * 8, arrayIndex = 0;
            byte nextChar = 0, bitsRemaining = 5;

            char[] returnArray = new char[charCount];

            foreach (byte b in input)
            {
                nextChar = (byte) (nextChar | (b >> (8 - bitsRemaining)));
                returnArray[arrayIndex++] = ValueToChar(nextChar);

                if (bitsRemaining < 4)
                {
                    nextChar = (byte) ((b >> (3 - bitsRemaining)) & 31);
                    returnArray[arrayIndex++] = ValueToChar(nextChar);
                    bitsRemaining += 5;
                }

                bitsRemaining -= 3;
                nextChar = (byte) ((b << bitsRemaining) & 31);
            }

            if (arrayIndex != charCount)
            {
                returnArray[arrayIndex++] = ValueToChar(nextChar);
                while (arrayIndex != charCount) returnArray[arrayIndex++] = '=';
            }

            return new string(returnArray);
        }

        private static int CharToValue(char value)
        {
            if (value < 91 && value > 64) return value - 65;
            if (value < 56 && value > 49) return value - 24;
            if (value < 123 && value > 96) return value - 97;

            throw new ArgumentException("Character is not a Base32 character.", nameof(value));
        }

        private static char ValueToChar(byte value)
        {
            if (value < 26) return (char) (value + 65);
            if (value < 32) return (char) (value + 24);

            throw new ArgumentException("Byte is not a Base32 value.", nameof(value));
        }
    }
}
