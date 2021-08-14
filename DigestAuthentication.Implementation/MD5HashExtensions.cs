using System;
using System.Security.Cryptography;
using System.Text;

namespace FlakeyBit.DigestAuthentication.Implementation
{
    internal static class MD5HashExtensions
    {
        public static string ToMD5Hash(this byte[] bytes) {
            var hashBytes = MD5.Create().ComputeHash(bytes);
            return BitConverter.ToString(hashBytes).Replace("-", "").ToLowerInvariant();
        }

        public static string ToMD5Hash(this string inputString) {
            return Encoding.UTF8.GetBytes(inputString).ToMD5Hash();
        }
    }
}