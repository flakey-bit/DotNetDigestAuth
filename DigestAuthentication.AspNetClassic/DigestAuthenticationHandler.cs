using System.Linq;
using System.Net;
using System.Security.Claims;
using System.Threading.Tasks;
using FlakeyBit.DigestAuthentication.Implementation;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;

namespace FlakeyBit.DigestAuthentication.AspNetClassic
{
    internal class DigestAuthenticationHandler : AuthenticationHandler<DigestAuthenticationOptions>
    {
        private readonly DigestAuthImplementation _digestAuth;

        public DigestAuthenticationHandler(DigestAuthenticationConfiguration config, IUsernameSecretProvider usernameSecretProvider) {
            _digestAuth = new DigestAuthImplementation(config, usernameSecretProvider);
        }

        protected override async Task<AuthenticationTicket> AuthenticateCoreAsync() {
            var properties = new AuthenticationProperties();

            if (!Request.Headers.TryGetValue(DigestAuthImplementation.AuthorizationHeaderName, out var headerValue)) {
                return new AuthenticationTicket(null, properties);
            }

            DigestChallengeResponse.TryParse(headerValue.FirstOrDefault(), out var challengeResponse);
			string validatedUsername = await _digestAuth.ValidateChallangeAsync(challengeResponse, Request.Method);

			if (validatedUsername == null) {
                return new AuthenticationTicket(null, properties);
            }

            var identity = new ClaimsIdentity(validatedUsername);
            identity.AddClaim(new Claim(DigestAuthImplementation.DigestAuthenticationClaimName, validatedUsername));

            if (_digestAuth.UseAuthenticationInfoHeader) {
	            Response.Headers[DigestAuthImplementation.AuthenticationInfoHeaderName] = await _digestAuth.BuildAuthInfoHeader(challengeResponse);
			}

			return new AuthenticationTicket(identity, properties);
        }

        protected override async Task ApplyResponseChallengeAsync() {
            await base.ApplyResponseChallengeAsync();

            if (Response.StatusCode == (int) HttpStatusCode.Unauthorized) {
                Response.Headers[DigestAuthImplementation.AuthenticateHeaderName] = _digestAuth.BuildChallengeHeader();
            }
        }
    }
}