using System.Threading.Tasks;
using FlakeyBit.DigestAuthentication.Implementation;

namespace AspNetCoreApp
{
    /// <summary>
    /// An example of how to implement IUsernameSecretProvider
    /// </summary>
    internal class TrivialUsernameSecretProvider : IUsernameSecretProvider
    {
        public Task<string> GetSecretForUsernameAsync(string username) {
            if (username == "eddie") {
                return Task.FromResult("starwars123");
            }

            return Task.FromResult<string>(null);
        }
    }
}