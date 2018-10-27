using FlakeyBit.DigestAuthentication.Implementation;
using Microsoft.AspNetCore.Authentication;

namespace FlakeyBit.DigestAuthentication.AspNetCore
{
    public class DigestAuthenticationOptions : AuthenticationSchemeOptions
    {
        public readonly DigestAuthenticationConfiguration Configuration = new DigestAuthenticationConfiguration();
    }
}