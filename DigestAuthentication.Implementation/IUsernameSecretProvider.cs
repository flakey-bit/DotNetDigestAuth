using System.Threading.Tasks;

namespace FlakeyBit.DigestAuthentication.Implementation
{
    public interface IUsernameSecretProvider
    {
        /// <summary>
        /// Mechanism to get the secret associated with a given username when generating the digest challenge
        /// </summary>
        /// <returns>The plaintext secret associated with the username, or null if the username is invalid</returns>
        Task<string> GetSecretForUsernameAsync(string username);
    }
}