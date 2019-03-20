using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FlakeyBit.DigestAuthentication.Implementation
{
    internal class DigestAuthImplementation
    {
        public static string AuthenticateHeaderName = "WWW-Authenticate";
        public static string AuthorizationHeaderName = "Authorization";
        public static string AuthenticationInfoHeaderName = "Authentication-Info";
        public static string DigestAuthenticationClaimName = "DIGEST_AUTHENTICATION_NAME";

        private static string QopMode = "auth";
        private static string NonceTimestampFormat = "yyyy-MM-dd HH:mm:ss.ffffffZ";
        private readonly DigestAuthenticationConfiguration _config;
        private readonly IUsernameSecretProvider _usernameSecretProvider;

        public DigestAuthImplementation(DigestAuthenticationConfiguration config, IUsernameSecretProvider usernameSecretProvider) {
            if (config == null) {
                throw new ArgumentNullException(nameof(config));
            }

            if (usernameSecretProvider == null) {
                throw new ArgumentNullException(nameof(usernameSecretProvider));
            }

            _config = config;
            _usernameSecretProvider = usernameSecretProvider;
        }

        public bool UseAuthenticationInfoHeader => _config.UseAuthenticationInfoHeader;

        public string BuildChallengeHeader() {

            var parts = new (string Key, string Value, bool ShouldQuote)[] {
                ("realm", _config.Realm, true),
                ("nonce", CreateNonce(DateTime.UtcNow), true),
                ("qop", QopMode, true),
                ("algorithm", "MD5", false)
            };

            return "Digest " + String.Join(", ", parts.Select(FormatHeaderComponent));
        }

		public async Task<string> BuildAuthInfoHeaderAsync(DigestChallengeResponse response) {
			var timestampStr = response.Nonce.Substring(0, NonceTimestampFormat.Length);
			var timestamp = ParseTimestamp(timestampStr);

			var delta = timestamp - DateTime.UtcNow;
			var deltaSeconds = Math.Abs(delta.TotalSeconds);

			List<ValueTuple<string, string, bool>> parts = new List<ValueTuple<string, string, bool>> {
				("qop", QopMode, true),
				("rspauth", await CreateRspAuth(response), true),
				("cnonce", response.ClientNonce, true),
				("nc", response.NonceCounter, false)
			};

			if (Math.Abs(deltaSeconds - _config.MaxNonceAgeSeconds) < _config.DeltaSecondsToNextNonce) {
				parts = parts.Prepend(("nextnonce", CreateNonce(DateTime.UtcNow), true)).ToList();
			}

			return String.Join(", ", parts.Select(FormatHeaderComponent));
		}

        private string FormatHeaderComponent((string Key, string Value, bool ShouldQuote) component) {
            if (component.ShouldQuote) {
                return $"{component.Key}=\"{component.Value}\"";
            }

            return $"{component.Key}={component.Value}";
        }
		
        public async Task<string> ValidateChallangeAsync(DigestChallengeResponse challengeResponse, string requestMethod) {
            if (challengeResponse == null) {
	            return null;
            }

            if (!ValidateNonce(challengeResponse)) {
                return null;
            }

            var secretForUsername = await _usernameSecretProvider.GetSecretForUsernameAsync(challengeResponse.Username);
            if (secretForUsername == null) {
                // Username not recognised
                return null;
            }

            var expectedHash = GenerateExpectedHash(challengeResponse, requestMethod, secretForUsername);

            if (expectedHash == challengeResponse.Response) {
                return challengeResponse.Username;
            }

            return null;
        }

        private string GenerateExpectedHash(DigestChallengeResponse response, string requestMethod, string secretForUsername) {
            var a1 = $"{response.Username}:{response.Realm}:{secretForUsername}";
            var a1Hash = a1.ToMD5Hash();

            var a2 = $"{requestMethod}:{response.Uri}";
            var a2Hash = a2.ToMD5Hash();

            return $"{a1Hash}:{response.Nonce}:{response.NonceCounter}:{response.ClientNonce}:{QopMode}:{a2Hash}".ToMD5Hash();
        }

        private async Task<string> CreateRspAuth(DigestChallengeResponse response)
        {
            var secretForUsername = await _usernameSecretProvider.GetSecretForUsernameAsync(response.Username);
            var a1 = $"{response.Username}:{response.Realm}:{secretForUsername}";
            var a1Hash = a1.ToMD5Hash();

            var a2 = $":{response.Uri}";
            var a2Hash = a2.ToMD5Hash();

            return $"{a1Hash}:{response.Nonce}:{response.NonceCounter}:{response.ClientNonce}:{QopMode}:{a2Hash}".ToMD5Hash();
        }

        private string CreateNonce(DateTime timestamp) {
            var builder = new StringBuilder();
            var timestampStr = timestamp.ToString(NonceTimestampFormat);
            builder.Append(timestampStr);
            builder.Append(" ");
            builder.Append($"{timestampStr}:{_config.ServerNonceSecret}".ToMD5Hash());

            return builder.ToString();
        }

        private bool ValidateNonce(DigestChallengeResponse challengeResponse) {
            try {
                var timestampStr = challengeResponse.Nonce.Substring(0, NonceTimestampFormat.Length);
                var timestamp = ParseTimestamp(timestampStr);

                var delta = timestamp - DateTime.UtcNow;

				if (Math.Abs(delta.TotalSeconds) > _config.MaxNonceAgeSeconds) {
                    return false;
                }

                return challengeResponse.Nonce == CreateNonce(timestamp.DateTime);
            } catch (Exception) {
                return false;
            }
        }

        private static DateTimeOffset ParseTimestamp(string timestampStr)
        {
            return DateTimeOffset.ParseExact(timestampStr, NonceTimestampFormat, CultureInfo.InvariantCulture);
        }
    }
}