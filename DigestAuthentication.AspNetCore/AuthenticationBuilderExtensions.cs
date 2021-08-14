using FlakeyBit.DigestAuthentication.Implementation;
using Microsoft.AspNetCore.Authentication;

namespace FlakeyBit.DigestAuthentication.AspNetCore
{
    public static class AuthenticationBuilderExtensions
    {
        public static AuthenticationBuilder AddDigestAuthentication(this AuthenticationBuilder builder,
                                                                    DigestAuthenticationConfiguration config) {
            return builder.AddScheme<DigestAuthenticationOptions, DigestAuthenticationHandler>("Digest",
                                                                                               "Digest",
                                                                                               options => {
                                                                                                   options.Configuration = config;
                                                                                               });
        }
    }
}