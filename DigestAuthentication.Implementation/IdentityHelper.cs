using System.Security.Claims;

namespace FlakeyBit.DigestAuthentication.Implementation
{
    public static class IdentityHelper
    {
        public static ClaimsIdentity CreateIdentityForUsername(string validatedUsername)
        {
            var identity = new ClaimsIdentity("Digest");
            identity.AddClaim(new Claim(DigestAuthImplementation.DigestAuthenticationClaimName, validatedUsername));
            identity.AddClaim(new Claim(ClaimsIdentity.DefaultNameClaimType, validatedUsername));
            return identity;
        }
    }
}