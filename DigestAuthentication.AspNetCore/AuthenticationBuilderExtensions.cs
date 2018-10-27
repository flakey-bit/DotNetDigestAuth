using System;
using Microsoft.AspNetCore.Authentication;

namespace FlakeyBit.DigestAuthentication.AspNetCore
{
    public static class AuthenticationBuilderExtensions
    {
        public static AuthenticationBuilder AddDigestAuthentication(this AuthenticationBuilder builder, Action<DigestAuthenticationOptions> configureOptions)
        {
            return builder.AddScheme<DigestAuthenticationOptions, DigestAuthenticationHandler>("Digest", "Digest", configureOptions);
        }
    }
}