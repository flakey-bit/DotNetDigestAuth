using Microsoft.Owin.Security;

namespace FlakeyBit.DigestAuthentication.AspNetClassic
{
    public class DigestAuthenticationOptions : AuthenticationOptions
    {
        internal DigestAuthenticationOptions() : base("Digest") {
        }
    }
}