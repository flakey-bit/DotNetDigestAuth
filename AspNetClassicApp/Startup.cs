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

            // Example configuration providing an IUsernameSecretProvider (which returns the secret for a given username in plaintext)
            // app.Use<DigestAuthenticationMiddleware>(DigestAuthenticationConfiguration.Create("VerySecure", "test-realm", 30, true, 20),
            //                                         new TrivialUsernameSecretProvider());

            // Example configuration using IUsernameHashedSecretProvider (which returns the pre-computed MD5 hash of the secret "A1")
            app.Use<DigestAuthenticationMiddleware>(DigestAuthenticationConfiguration.Create("VerySecure", "test-realm", 30, true, 20),
                                                    new TrivialUsernameHashedSecretProvider());
            app.UseWebApi(config);
        }
    }
}