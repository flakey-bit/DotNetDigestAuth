using FlakeyBit.DigestAuthentication.Implementation;
using Microsoft.Owin;
using Microsoft.Owin.Security.Infrastructure;

namespace FlakeyBit.DigestAuthentication.AspNetClassic
{
    public class DigestAuthenticationMiddleware : AuthenticationMiddleware<DigestAuthenticationOptions>
    {
        private readonly DigestAuthenticationConfiguration _config;
        private readonly IUsernameHashedSecretProvider _usernameHashedSecretProvider;
        private readonly IUsernameSecretProvider _usernameSecretProvider;

        public DigestAuthenticationMiddleware(OwinMiddleware next, DigestAuthenticationConfiguration config, IUsernameHashedSecretProvider usernameHashedSecretProvider) :
            base(next, new DigestAuthenticationOptions()) {
            _config = config;
            _usernameHashedSecretProvider = usernameHashedSecretProvider;
        }

        public DigestAuthenticationMiddleware(OwinMiddleware next, DigestAuthenticationConfiguration config, IUsernameSecretProvider usernameSecretProvider) :
            base(next, new DigestAuthenticationOptions())
        {
            _config = config;
            _usernameSecretProvider = usernameSecretProvider;
        }

        protected override AuthenticationHandler<DigestAuthenticationOptions> CreateHandler() {
            if (_usernameHashedSecretProvider != null) {
                return new DigestAuthenticationHandler(_config, _usernameHashedSecretProvider);
            }

            return new DigestAuthenticationHandler(_config, new UsernameHashedSecretComputer(_usernameSecretProvider));
        }
    }
}