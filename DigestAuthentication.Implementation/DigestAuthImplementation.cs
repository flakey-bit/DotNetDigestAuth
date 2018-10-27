using System;
using System.Globalization;
using System.Linq;
using System.Text;

namespace FlakeyBit.DigestAuthentication.Implementation
{
    internal class DigestAuthImplementation
    {
        public static string AuthenticateHeaderName = "WWW-Authenticate";
        public static string AuthorizationHeaderName = "Authorization";
        public static string DigestAuthenticationClaimName = "DIGEST_AUTHENTICATION_NAME";

        private static string QopMode = "auth";
        private static string NonceTimestampFormat = "yyyy-MM-dd HH:mm:ss.ffffffZ";
        private readonly DigestAuthenticationConfiguration _config;

        public DigestAuthImplementation(DigestAuthenticationConfiguration config) {
            _config = config;
        }

        public string BuildChallengeHeader()
        {
            string nonce = CreateNonce(DateTime.UtcNow);

            var parts = new(string Key, string Value)[] {
                ("realm", _config.Realm),
                ("nonce", nonce),
                ("qop", QopMode)
            };

            return "Digest " + String.Join(", ", parts.Select(pair => $"{pair.Key}=\"{pair.Value}\""));
        }

        public bool ValidateChallange(string authorizationHeaderValue, string requestMethod, out string username)
        {
            username = null;

            if (!DigestChallengeResponse.TryParse(authorizationHeaderValue, out var challengeResponse))
            {
                return false;
            }

            if (!ValidateNonce(challengeResponse))
            {
                return false;
            }

            var expectedHash = GenerateExpectedHash(challengeResponse, requestMethod);

            if (expectedHash == challengeResponse.Response)
            {
                username = challengeResponse.Username;
                return true;
            }


            return false;
        }

        private string GenerateExpectedHash(DigestChallengeResponse response, string requestMethod)
        {
            // FIXME: !!!
            const string expectedSecret = "password";

            var a1 = $"{response.Username}:{response.Realm}:{expectedSecret}";
            var a1Hash = a1.ToMD5Hash();

            var a2 = $"{requestMethod}:{response.Uri}";
            var a2Hash = a2.ToMD5Hash();

            return $"{a1Hash}:{response.Nonce}:{response.NonceCounter}:{response.ClientNonce}:{QopMode}:{a2Hash}".ToMD5Hash();
        }

        private string CreateNonce(DateTime timestamp)
        {
            var builder = new StringBuilder();
            var timestampStr = timestamp.ToString(NonceTimestampFormat);
            builder.Append(timestampStr);
            builder.Append(" ");
            builder.Append($"{timestampStr}:{_config.ServerNonceSecret}".ToMD5Hash());

            return builder.ToString();
        }

        private bool ValidateNonce(DigestChallengeResponse challengeResponse)
        {
            try
            {
                var timestampStr = challengeResponse.Nonce.Substring(0, NonceTimestampFormat.Length);
                var timestamp = DateTimeOffset.ParseExact(timestampStr, NonceTimestampFormat, CultureInfo.InvariantCulture);

                var delta = timestamp - DateTime.UtcNow;

                if (Math.Abs(delta.TotalSeconds) > _config.MaxNonceAgeSeconds)
                {
                    return false;
                }

                return challengeResponse.Nonce == CreateNonce(timestamp.DateTime);
            }
            catch (Exception)
            {
                return false;
            }
        }
    }
}