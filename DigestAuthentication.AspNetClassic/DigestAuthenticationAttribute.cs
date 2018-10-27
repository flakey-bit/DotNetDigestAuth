using System.Security.Claims;
using System.Web.Mvc;
using FlakeyBit.DigestAuthentication.Implementation;

namespace FlakeyBit.DigestAuthMiddleware.AspNetClassic
{
    public class DigestAuthenticationAttribute : AuthorizeAttribute
    {
        public override void OnAuthorization(AuthorizationContext filterContext)
        {
            var user = filterContext.HttpContext.User as ClaimsPrincipal;
            if (user != null && user.HasClaim(claim => claim.Type == DigestAuthImplementation.DigestAuthenticationClaimName))
            {
                base.OnAuthorization(filterContext);
            }
            else
            {
                HandleUnauthorizedRequest(filterContext);
            }
        }
    }
}