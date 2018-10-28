#if NETSTANDARD1_3
using System.Security.Cryptography;
#endif
using System.Text;

namespace FlakeyBit.DigestAuthentication.Implementation
{
    internal static class MD5HashExtensions
    {
#if NETSTANDARD1_3
        public static string ToMD5Hash(this byte[] bytes) {
            var hashBytes = System.Security.Cryptography.MD5.Create().ComputeHash(bytes);
            return System.BitConverter.ToString(hashBytes).Replace("-", "").ToLowerInvariant();
        }
#endif

        public static string ToMD5Hash(this string inputString) {
#if NETSTANDARD1_3
            return Encoding.UTF8.GetBytes(inputString).ToMD5Hash();
#else
            return MD5.Calculate(Encoding.UTF8.GetBytes(inputString));
#endif
        }
    }
}