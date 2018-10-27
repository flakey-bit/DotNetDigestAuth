using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using FlakeyBit.DigestAuthentication.Implementation;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace FlakeyBit.DigestAuthentication.AspNetCore
{
    internal class DigestAuthenticationHandler : AuthenticationHandler<DigestAuthenticationOptions>
    {
        public DigestAuthenticationHandler(IOptionsMonitor<DigestAuthenticationOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock)
            : base(options, logger, encoder, clock) {
            
        }

        protected override async Task<AuthenticateResult> HandleAuthenticateAsync() {
            var digestAuth = new DigestAuthImplementation(Options.Configuration, Options.UsernameSecretProvider);

            if (!Request.Headers.TryGetValue(DigestAuthImplementation.AuthorizationHeaderName, out var headerValue)) {
                Response.Headers[DigestAuthImplementation.AuthenticateHeaderName] = digestAuth.BuildChallengeHeader();
                return AuthenticateResult.NoResult();
            }

            string validatedUsername = await digestAuth.ValidateChallangeAsync(headerValue, Request.Method);

            if (validatedUsername == null) {
                Response.Headers[DigestAuthImplementation.AuthenticateHeaderName] = digestAuth.BuildChallengeHeader();
                return AuthenticateResult.NoResult();
            }

            var identity = new ClaimsIdentity(validatedUsername);
            identity.AddClaim(new Claim(DigestAuthImplementation.DigestAuthenticationClaimName, validatedUsername));
            var principal = new ClaimsPrincipal(identity);

            return AuthenticateResult.Success(new AuthenticationTicket(principal, new AuthenticationProperties(), Scheme.Name));
        }
    }
}