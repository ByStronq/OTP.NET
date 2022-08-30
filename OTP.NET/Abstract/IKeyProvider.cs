using OTP.NET.Concrete;

namespace OTP.NET.Abstract
{
    public interface IKeyProvider
    {
        byte[] ComputeHmac(OTPHashMode mode, byte[] data);
    }
}
