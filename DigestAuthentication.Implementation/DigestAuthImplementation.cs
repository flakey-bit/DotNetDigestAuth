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
        public const string AuthenticateHeaderName = "WWW-Authenticate";
        public const string AuthorizationHeaderName = "Authorization";
        public const string AuthenticationInfoHeaderName = "Authentication-Info";
        public const string DigestAuthenticationClaimName = "DIGEST_AUTHENTICATION_NAME";

        private const string QopMode = "auth";
        private const string NonceTimestampFormat = "yyyy-MM-dd HH:mm:ss.ffffffZ";

        private readonly DigestAuthenticationConfiguration _config;
        private readonly IUsernameHashedSecretProvider _usernameHashedSecretProvider;
        private readonly IClock _clock;

        public DigestAuthImplementation(DigestAuthenticationConfiguration config, IUsernameHashedSecretProvider usernameHashedSecretProvider, IClock clock)
        {
            if (config == null) {
                throw new ArgumentNullException(nameof(config));
            }

            if (usernameHashedSecretProvider == null) {
                throw new ArgumentNullException(nameof(usernameHashedSecretProvider));
            }

            if (clock == null) {
                throw new ArgumentNullException(nameof(clock));
            }

            _config = config;
            _usernameHashedSecretProvider = usernameHashedSecretProvider;
            _clock = clock;
        }

        public bool UseAuthenticationInfoHeader => _config.UseAuthenticationInfoHeader;

        public string BuildChallengeHeader() {
            var parts = new (string Key, string Value, bool ShouldQuote)[] {
                ("realm", _config.Realm, true),
                ("nonce", CreateNonce(_clock.UtcNow), true),
                ("qop", QopMode, true),
                ("algorithm", "MD5", false)
            };

            return "Digest " + String.Join(", ", parts.Select(FormatHeaderComponent));
        }

		public async Task<string> BuildAuthInfoHeaderAsync(DigestChallengeResponse response) {
			var timestampStr = response.Nonce.Substring(0, NonceTimestampFormat.Length);
			var timestamp = ParseTimestamp(timestampStr);

			var delta = timestamp - _clock.UtcNow;
			var deltaSeconds = Math.Abs(delta.TotalSeconds);

		    string a1Hash = await _usernameHashedSecretProvider.GetA1Md5HashForUsernameAsync(response.Username, _config.Realm);

			List<ValueTuple<string, string, bool>> parts = new List<ValueTuple<string, string, bool>> {
				("qop", QopMode, true),
				("rspauth", CreateRspAuth(response, a1Hash), true),
				("cnonce", response.ClientNonce, true),
				("nc", response.NonceCounter, false)
			};

			if (Math.Abs(deltaSeconds - _config.MaxNonceAgeSeconds) < _config.DeltaSecondsToNextNonce) {
				parts = parts.Prepend(("nextnonce", CreateNonce(_clock.UtcNow), true)).ToList();
			}

			return String.Join(", ", parts.Select(FormatHeaderComponent));
		}
		
        public async Task<string> ValidateChallangeAsync(DigestChallengeResponse challengeResponse, string requestMethod) {
            if (challengeResponse == null) {
	            throw new ArgumentNullException(nameof(challengeResponse));
            }

            if (!ValidateNonce(challengeResponse)) {
                return null;
            }

            var a1Hash = await _usernameHashedSecretProvider.GetA1Md5HashForUsernameAsync(challengeResponse.Username, _config.Realm);
            if (a1Hash == null) {
                // Username not recognised
                return null;
            }

            var expectedHash = GenerateExpectedHash(challengeResponse, requestMethod, a1Hash);

            if (expectedHash == challengeResponse.Response) {
                return challengeResponse.Username;
            }

            return null;
        }

        private string FormatHeaderComponent((string Key, string Value, bool ShouldQuote) component) {
            if (component.ShouldQuote)
            {
                return $"{component.Key}=\"{component.Value}\"";
            }

            return $"{component.Key}={component.Value}";
        }

        private string GenerateExpectedHash(DigestChallengeResponse response, string requestMethod, string a1Hash) {
            var a2 = $"{requestMethod}:{response.Uri}";
            var a2Hash = a2.ToMD5Hash();

            return $"{a1Hash}:{response.Nonce}:{response.NonceCounter}:{response.ClientNonce}:{QopMode}:{a2Hash}".ToMD5Hash();
        }

        private string CreateRspAuth(DigestChallengeResponse response, string a1Hash)
        {
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

                var delta = timestamp - _clock.UtcNow;

				if (Math.Abs(delta.TotalSeconds) > _config.MaxNonceAgeSeconds) {
                    return false;
                }

                return challengeResponse.Nonce == CreateNonce(timestamp.DateTime);
            } catch (Exception) {
                return false;
            }
        }

        private static DateTimeOffset ParseTimestamp(string timestampStr) {
            return DateTimeOffset.ParseExact(timestampStr, NonceTimestampFormat, CultureInfo.InvariantCulture);
        }
    }
}