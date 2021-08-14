using FlakeyBit.DigestAuthentication.Implementation;
using Microsoft.AspNetCore.Authentication;

namespace FlakeyBit.DigestAuthentication.AspNetCore
{
    public static class AuthenticationBuilderExtensions
    {
        /// <summary>
        /// Enables digest authentication
        /// </summary>
        /// <param name="builder">The <see cref="AuthenticationBuilder"/></param>
        /// <param name="config">Mandatory configuration for Digest Authentication</param>
        /// <returns>A reference to builder after the operation has completed.</returns>
        public static AuthenticationBuilder AddDigestAuthentication(this AuthenticationBuilder builder, DigestAuthenticationConfiguration config) =>
            builder.AddDigestAuthentication(config, "Digest", "Digest");

        /// <summary>
        /// Enables digest authentication
        /// </summary>
        /// <param name="builder">The <see cref="AuthenticationBuilder"/></param>
        /// <param name="config">Mandatory configuration for Digest Authentication</param>
        /// <param name="authenticationScheme">The authentication scheme.</param>
        /// <param name="displayName">The display name for the authentication handler.</param>
        /// <returns>A reference to builder after the operation has completed.</returns>        
        public static AuthenticationBuilder AddDigestAuthentication(this AuthenticationBuilder builder,
                                                                    DigestAuthenticationConfiguration config,
                                                                    string authenticationScheme,
                                                                    string displayName) {
            return builder.AddScheme<DigestAuthenticationOptions, DigestAuthenticationHandler>(authenticationScheme,
                                                                                               displayName,
                                                                                               options => { options.Configuration = config; });
        }
    }
}