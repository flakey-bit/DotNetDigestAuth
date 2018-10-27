using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using FlakeyBit.DigestAuthentication.Implementation;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace FlakeyBit.DigestAuthentication.AspNetCore
{
    public class DigestAuthenticationHandler : AuthenticationHandler<DigestAuthenticationOptions>
    {
        private readonly DigestAuthImplementation _digestAuth;

        public DigestAuthenticationHandler(IOptionsMonitor<DigestAuthenticationOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock)
            : base(options, logger, encoder, clock) {
            _digestAuth = new DigestAuthImplementation(options.CurrentValue.Configuration);
        }

        protected override Task<AuthenticateResult> HandleAuthenticateAsync() {
            if (!Request.Headers.TryGetValue(DigestAuthImplementation.AuthorizationHeaderName, out var headerValue)) {
                Response.Headers[DigestAuthImplementation.AuthenticateHeaderName] = _digestAuth.BuildChallengeHeader();
                return Task.FromResult(AuthenticateResult.NoResult());
            }

            if (!_digestAuth.ValidateChallange(headerValue, Request.Method, out var username)) {
                Response.Headers[DigestAuthImplementation.AuthenticateHeaderName] = _digestAuth.BuildChallengeHeader();
                return Task.FromResult(AuthenticateResult.NoResult());
            }

            var identity = new ClaimsIdentity(username);
            identity.AddClaim(new Claim(DigestAuthImplementation.DigestAuthenticationClaimName, username));
            var principal = new ClaimsPrincipal(identity);

            return Task.FromResult(
                AuthenticateResult.Success(
                    new AuthenticationTicket(
                        principal,
                        new AuthenticationProperties(),
                        Scheme.Name)));
        }
    }
}