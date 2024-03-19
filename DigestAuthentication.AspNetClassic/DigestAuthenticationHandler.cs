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

        public DigestAuthenticationHandler(DigestAuthenticationConfiguration config, IUsernameHashedSecretProvider usernameHashedSecretProvider, IClock clock) {
            _digestAuth = new DigestAuthImplementation(config, usernameHashedSecretProvider, clock);
        }

        protected override async Task<AuthenticationTicket> AuthenticateCoreAsync() {
            var properties = new AuthenticationProperties();

            if (!Request.Headers.TryGetValue(DigestAuthImplementation.AuthorizationHeaderName, out var headerValue)) {
                return new AuthenticationTicket(null, properties);
            }

            if (!DigestChallengeResponse.TryParse(headerValue.FirstOrDefault(), out var challengeResponse)) {
                return new AuthenticationTicket(null, properties);
            }

            string validatedUsername = await _digestAuth.ValidateChallangeAsync(challengeResponse, Request.Method);

            if (validatedUsername == null) {
                return new AuthenticationTicket(null, properties);
            }

            ClaimsIdentity identity = CreateIdentityFromValidatedUserName(validatedUsername);

            if (_digestAuth.UseAuthenticationInfoHeader) {
                Response.Headers[DigestAuthImplementation.AuthenticationInfoHeaderName] = await _digestAuth.BuildAuthInfoHeaderAsync(challengeResponse);
            }

            return new AuthenticationTicket(identity, properties);
        }

        internal ClaimsIdentity CreateIdentityFromValidatedUserName(string validatedUsername)
        {
            var identity = new ClaimsIdentity("Digest");
            identity.AddClaim(new Claim(DigestAuthImplementation.DigestAuthenticationClaimName, validatedUsername));

            //Remember to add the ClaimsIdentity::DefaultNameClaimType to allow ClaimsIdentity to have a name #24
            identity.AddClaim(new Claim(ClaimsIdentity.DefaultNameClaimType, validatedUsername));
            return identity;
        }

        protected override async Task ApplyResponseChallengeAsync() {
            await base.ApplyResponseChallengeAsync();

            if (Response.StatusCode == (int) HttpStatusCode.Unauthorized) {
                Response.Headers[DigestAuthImplementation.AuthenticateHeaderName] = _digestAuth.BuildChallengeHeader();
            }
        }
    }
}