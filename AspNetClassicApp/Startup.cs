using System.Web.Http;
using FlakeyBit.DigestAuthentication.AspNetClassic;
using FlakeyBit.DigestAuthentication.Implementation;
using Microsoft.Owin;
using Owin;

[assembly: OwinStartup(typeof(AspNetClassicApp.Startup))]

namespace AspNetClassicApp
{
    public class Startup
    {
        public void Configuration(IAppBuilder app) {
            HttpConfiguration config = new HttpConfiguration();
            config.Routes.MapHttpRoute(name: "DefaultApi",
                                       routeTemplate: "api/{controller}/{id}",
                                       defaults: new {
                                           id = RouteParameter.Optional
                                       });

            app.Use<DigestAuthenticationMiddleware>(DigestAuthenticationConfiguration.Create("VerySecure", "test-realm", 30, true, 20),
                                                    new TrivialUsernameSecretProvider());
            app.UseWebApi(config);
        }
    }
}