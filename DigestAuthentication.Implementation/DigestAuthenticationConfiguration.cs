using System;

namespace FlakeyBit.DigestAuthentication.Implementation
{
    public class DigestAuthenticationConfiguration
    {
        public string ServerNonceSecret { get; }
        public string Realm { get; }
        public long MaxNonceAgeSeconds { get; }

        private DigestAuthenticationConfiguration(string serverNonceSecret, string realm, long maxNonceAgeSeconds) {
            if (string.IsNullOrEmpty(serverNonceSecret) || serverNonceSecret.Length < 5) {
                throw new ArgumentException("Server nonce secret must be at least 5 characters long");
            }

            if (string.IsNullOrEmpty(realm)) {
                throw new ArgumentException("Realm is required");
            }

            if (maxNonceAgeSeconds < 0) {
                throw new ArgumentException("Max nonce age must be positive");
            }

            ServerNonceSecret = serverNonceSecret;
            Realm = realm;
            MaxNonceAgeSeconds = maxNonceAgeSeconds;
        }

        public static DigestAuthenticationConfiguration Create(string serverNonceSecret, string realm, long maxNonceAgeSeconds = 3600) {
            return new DigestAuthenticationConfiguration(serverNonceSecret, realm, maxNonceAgeSeconds);
        }
    }
}