using System.Net;
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
        private DigestAuthImplementation _digestAuth;

        public DigestAuthenticationHandler(IOptionsMonitor<DigestAuthenticationOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock)
            : base(options, logger, encoder, clock) {
        }

        protected override async Task InitializeHandlerAsync() {
            await base.InitializeHandlerAsync();
            _digestAuth = new DigestAuthImplementation(Options.Configuration, Options.UsernameSecretProvider);
        }

        protected override async Task<AuthenticateResult> HandleAuthenticateAsync() {
            if (!Request.Headers.TryGetValue(DigestAuthImplementation.AuthorizationHeaderName, out var headerValue)) {
                return AuthenticateResult.NoResult();
            }

            string validatedUsername = await _digestAuth.ValidateChallangeAsync(headerValue, Request.Method);

            if (validatedUsername == null) {
                return AuthenticateResult.NoResult();
            }

            var identity = new ClaimsIdentity(validatedUsername);
            identity.AddClaim(new Claim(DigestAuthImplementation.DigestAuthenticationClaimName, validatedUsername));
            var principal = new ClaimsPrincipal(identity);

            return AuthenticateResult.Success(new AuthenticationTicket(principal, new AuthenticationProperties(), Scheme.Name));
        }

        protected override async Task HandleChallengeAsync(AuthenticationProperties properties) {
            await base.HandleChallengeAsync(properties);

            if (Response.StatusCode == (int) HttpStatusCode.Unauthorized) {
                Response.Headers[DigestAuthImplementation.AuthenticateHeaderName] = _digestAuth.BuildChallengeHeader();
            }
        }
    }
}