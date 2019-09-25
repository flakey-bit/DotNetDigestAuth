using System.Threading.Tasks;
using FlakeyBit.DigestAuthentication.Implementation;

namespace AspNetCoreApp
{
    /// <summary>
    /// An example of how to implement IUsernameHashedSecretProvider
    /// </summary>
    internal class TrivialUsernameHashedSecretProvider : IUsernameHashedSecretProvider
    {
        public Task<string> GetA1Md5HashForUsernameAsync(string username, string realm) {
            if (username == "eddie" && realm == "some-realm") {
                // The hash value below would have been pre-computed & stored in the database.
                //var hash = DigestAuthentication.ComputeA1Md5Hash("eddie", "some-realm", "starwars123");
                const string hash = "d388783882abeb762de9801d4379570b";
                
                return Task.FromResult(hash);
            }

            // User not found
            return Task.FromResult<string>(null);
        }
    }
}