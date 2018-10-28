using FlakeyBit.DigestAuthentication.Implementation;
using Microsoft.Owin;
using Microsoft.Owin.Security.Infrastructure;

namespace FlakeyBit.DigestAuthentication.AspNetClassic
{
    public class DigestAuthenticationMiddleware : AuthenticationMiddleware<DigestAuthenticationOptions>
    {
        private readonly DigestAuthenticationConfiguration _config;
        private readonly IUsernameSecretProvider _usernameSecretProvider;

        public DigestAuthenticationMiddleware(OwinMiddleware next, DigestAuthenticationConfiguration config, IUsernameSecretProvider usernameSecretProvider) :
            base(next, new DigestAuthenticationOptions()) {
            _config = config;
            _usernameSecretProvider = usernameSecretProvider;
        }

        protected override AuthenticationHandler<DigestAuthenticationOptions> CreateHandler() {
            return new DigestAuthenticationHandler(_config, _usernameSecretProvider);
        }
    }
}