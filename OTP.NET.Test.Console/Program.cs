using OTP.NET.Concrete;

var mode = OTPHashMode.Sha512;

var key = KeyGeneration.GenerateRandomKey(mode);

var base32String = Base32Encoding.ToString(key);

Console.WriteLine($"Key: {base32String}\n");
Console.WriteLine($"Base64: {Convert.ToBase64String(key)}\n");

var base32Bytes = Base32Encoding.ToBytes(base32String);

string? tempOtpCode = null;
int? tempOtpRemainingTime = null;

long counter = 0;

while (true)
{
    /*

    #region TOTP

        var totp = new TOTP(base32Bytes, mode: mode, step: 15, totpSize: 8);

        var totpCode = totp.ComputeTotp();

        if (tempOtpCode != totpCode)
        {
            tempOtpCode = totpCode;

            ClearCurrentConsoleLine();

            Console.WriteLine(totpCode);
        }

        var totpRemainingTime = totp.RemainingSeconds();

        if (tempOtpRemainingTime != totpRemainingTime)
        {
            tempOtpRemainingTime = totpRemainingTime;

            ClearCurrentConsoleLine();

            Console.Write(totpRemainingTime);
        }

    #endregion

    */

    // /*

    #region HOTP

        var hotp = new HOTP(base32Bytes, mode: mode, hotpSize: 8);

        var hotpCode = hotp.ComputeHOTP(counter++);

        if (tempOtpCode != hotpCode)
        {
            tempOtpCode = hotpCode;

            ClearCurrentConsoleLine();

            Console.WriteLine(hotpCode);
        }

        Console.ReadKey();

    #endregion

    // */
}

static void ClearCurrentConsoleLine()
{
    int currentLineCursor = Console.CursorTop;
    Console.SetCursorPosition(0, Console.CursorTop);
    Console.Write(new string(' ', Console.WindowWidth)); 
    Console.SetCursorPosition(0, currentLineCursor);
}
