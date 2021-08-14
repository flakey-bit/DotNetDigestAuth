using System.Threading.Tasks;
using FlakeyBit.DigestAuthentication.Implementation;

namespace AspNetClassicApp
{
    /// <summary>
    /// An example of how to implement IUsernameHashedSecretProvider
    /// </summary>
    internal class TrivialUsernameHashedSecretProvider : IUsernameHashedSecretProvider
    {
        public Task<string> GetA1Md5HashForUsernameAsync(string username, string realm) {
            if (username == "eddie" && realm == "test-realm") {
                // The hash value below would have been pre-computed & stored in the database.
                //var hash = DigestAuthentication.ComputeA1Md5Hash("eddie", "test-realm", "starwars123");
                const string hash = "56bde614dc75372a1ef4323904f3beb7";

                return Task.FromResult(hash);
            }

            // User not found
            return Task.FromResult<string>(null);
        }
    }
}