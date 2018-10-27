using System.Web.Http;

namespace AspNetClassicApp.Controllers
{
    public class OpenController : ApiController
    {
        public string Get() {
            return "Public info!";
        }
    }
}