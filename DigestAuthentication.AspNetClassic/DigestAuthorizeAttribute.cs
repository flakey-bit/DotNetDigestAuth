using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Web.Http.Controllers;
using System.Web.Http.Filters;
using FlakeyBit.DigestAuthentication.Implementation;

namespace FlakeyBit.DigestAuthentication.AspNetClassic
{
    public class DigestAuthorizeAttribute : AuthorizationFilterAttribute
    {
        public override void OnAuthorization(HttpActionContext actionContext) {
            var user = actionContext.RequestContext.Principal as ClaimsPrincipal;

            if (user != null && user.HasClaim(claim => claim.Type == DigestAuthImplementation.DigestAuthenticationClaimName)) {
                return;
            }

            actionContext.Response = new HttpResponseMessage(HttpStatusCode.Unauthorized);
        }
    }
}