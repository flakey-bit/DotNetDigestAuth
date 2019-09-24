using FlakeyBit.DigestAuthentication.Implementation;
using Microsoft.AspNetCore.Authentication;

namespace FlakeyBit.DigestAuthentication.AspNetCore
{
    internal class DigestAuthenticationOptions : AuthenticationSchemeOptions
    {
        public DigestAuthenticationConfiguration Configuration;
    }
}