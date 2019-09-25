using System;
using System.Threading.Tasks;

namespace FlakeyBit.DigestAuthentication.Implementation
{
    internal class UsernameHashedSecretComputer : IUsernameHashedSecretProvider
    {
        private readonly IUsernameSecretProvider _usernameSecretProvider;

        public UsernameHashedSecretComputer(IUsernameSecretProvider usernameSecretProvider)
        {
            if (usernameSecretProvider == null) {
                throw new ArgumentNullException(nameof(usernameSecretProvider));
            }

            _usernameSecretProvider = usernameSecretProvider;
        }

        public async Task<string> GetA1Md5HashForUsernameAsync(string username, string realm) {
            var secret = await _usernameSecretProvider.GetSecretForUsernameAsync(username);
            if (secret == null) {
                // Username not recognised
                return null;
            }

            return DigestAuthentication.ComputeA1Md5Hash(username, realm, secret);
        }
    }
}