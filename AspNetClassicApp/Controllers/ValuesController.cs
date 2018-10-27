using System.Web.Http;
using FlakeyBit.DigestAuthMiddleware.AspNetClassic;

namespace AspNetClassicApp.Controllers
{
    public class ValuesController : ApiController
    {
        [DigestAuthentication]
        public string Get() {
            return "Hello World";
        }
    }
}
