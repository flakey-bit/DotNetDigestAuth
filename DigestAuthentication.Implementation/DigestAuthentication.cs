namespace FlakeyBit.DigestAuthentication.Implementation
{
    public static class DigestAuthentication
    {
        /// <summary>
        /// Method to pre-compute the "A1" MD5 hash for storing in the database (rather than storing user passwords in plaintext)
        /// </summary>
        /// <returns>The computed "A1" MD5 hash suitable for returning via <see cref="IUsernameHashedSecretProvider"/></returns>
        public static string ComputeA1Md5Hash(string username, string realm, string secret) {
            var a1 = $"{username}:{realm}:{secret}";
            return a1.ToMD5Hash();
        }
    }
}