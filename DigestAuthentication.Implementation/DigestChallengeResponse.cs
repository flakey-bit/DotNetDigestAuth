using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace FlakeyBit.DigestAuthentication.Implementation
{
    internal class DigestChallengeResponse
    {
        private static readonly Regex ChallengeResponseRegex = new Regex("(?<key>\\w+)[:=](?<value>[\\s\"]?(([^\",]|(\\\"))+))\"?", RegexOptions.IgnoreCase);

        public string Realm { get; }
        public string Uri { get; }
        public string Username { get; }
        public string Nonce { get; }
        public string NonceCounter { get; }
        public string ClientNonce { get; }
        public string Response { get; }

        public DigestChallengeResponse(string realm, string uri, string username, string nonce, string nonceCounter, string clientNonce, string response) {
            Realm = realm;
            Uri = uri;
            Username = username;
            Nonce = nonce;
            NonceCounter = nonceCounter;
            ClientNonce = clientNonce;
            Response = response;
        }

        public static bool TryParse(string authorizationHeaderValue, out DigestChallengeResponse response) {
            response = null;
            try {
                if (string.IsNullOrEmpty(authorizationHeaderValue)) {
                    return false;
                }

                if (!authorizationHeaderValue.StartsWith("Digest ")) {
                    return false;
                }

                var digestPart = authorizationHeaderValue.Substring("Digest ".Length);
                var matches = ChallengeResponseRegex.Matches(digestPart);

                var parts = new Dictionary<string, string>();
                for (var i = 0; i < matches.Count; i++) {
                    var key = matches[i].Groups["key"].Value;
                    var value = matches[i].Groups["value"].Value;

                    if (value.StartsWith("\""))
                    {
                        value = value.Substring(1, value.Length - 2);
                    }

                    parts[key] = value;
                }

                var username = parts["username"];
                var realm = parts["realm"];
                var nonce = parts["nonce"];
                var uri = parts["uri"];
                var nonceCounter = parts["nc"];
                var clientNonce = parts["cnonce"];
                var responseValue = parts["response"];

                response = new DigestChallengeResponse(realm, uri, username, nonce, nonceCounter, clientNonce, responseValue);
                return true;
            } catch (Exception) {
                return false;
            }
        }
    }
}