using System.Web.Http;
using FlakeyBit.DigestAuthentication.AspNetClassic;

namespace AspNetClassicApp.Controllers
{
    public class ValuesController : ApiController
    {
        [DigestAuthorize]
        public string Get() {
            return "Protected info!";
        }
    }
}