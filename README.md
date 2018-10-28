# DotNetDigestAuth
Implementation of Digest Authentication for ASP.NET Core (AuthenticationHandler) &amp; ASP.NET (OWIN Middleware).

Supports: ASP.NET running on .NET Framework 4.6.1+ or ASP.NET Core running on .NET Standard 2.0+ 

## General:
- You'll need to reference the NuGet package & namespace `FlakeyBit.DigestAuthentication.Implementation` - this contains the core implementation of the Digest authentication as well as some interfaces/classes for configuring things.

- You'll need to provide an implementation of `IUsernameSecretProvider` - a trivial example is given below:

```C#
    /// <summary>
    /// An example of how to implement IUsernameSecretProvider
    /// </summary>
    internal class ExampleUsernameSecretProvider : IUsernameSecretProvider
    {
        public Task<string> GetSecretForUsernameAsync(string username) {
            if (username == "eddie") {
                return Task.FromResult("starwars123");
            }

            // Return value of null indicates unknown (invalid) user
            return Task.FromResult<string>(null);
        }
    }
```

### DigestAuthenticationConfiguration.Create:
`DigestAuthenticationConfiguration.Create` is used to configure the digest authentication.

* `ServerNonceSecret` is used when generating the challenges for the client. Keep this safe!
* `Realm` describes (to the user) the computer or system being accessed
* `MaxNonceAgeSeconds` is the number of seconds a given nonce is valid for. After that point, the client will be prompted to reauthenticate

E.g.

```C#
DigestAuthenticationConfiguration.Create("SomeVerySecureServerNonceSecret", "SomeDescriptiveRealmName", 30)
```

## Usage in ASP.NET Core:

- You'll want to reference the NuGet package & namespace `FlakeyBit.DigestAuthentication.AspNetCore`.

In your web host startup:

```C#
public class Startup
{
        public void ConfigureServices(IServiceCollection services) {
            services.AddAuthentication("Digest")
                    .AddDigestAuthentication(DigestAuthenticationConfiguration.Create("SomeVerySecureServerNonceSecret", "SomeDescriptiveRealmName", 30),
                                             new ExampleUsernameSecretProvider());
            services.AddMvc();
        }
}
```

This will add a claim of type `DIGEST_AUTHENTICATION_NAME` (value will be the authenticated user name) to the principal on the request context. If you want to simply check for a claim of this type on a controller action, you can use the `[Authorize]` attribute as follows:

```C#
    [Route("api/[controller]")]
    public class ValuesController : Controller
    {
        // GET api/values
        [HttpGet]
        [Authorize(AuthenticationSchemes = "Digest")]
        public string Get() {
            return "Hello Core!";
        }
    }
```

## Usage in ASP.NET Classic:

- You'll want to reference the NuGet package & namespace `FlakeyBit.DigestAuthentication.AspNetClassic`.

In your web host startup:

```C#
    public class Startup
    {
        public void Configuration(IAppBuilder app) {
            HttpConfiguration config = new HttpConfiguration();
            config.Routes.MapHttpRoute(name: "DefaultApi",
                                       routeTemplate: "api/{controller}/{id}",
                                       defaults: new {
                                           id = RouteParameter.Optional
                                       });

            app.Use<DigestAuthenticationMiddleware>(DigestAuthenticationConfiguration.Create("SomeVerySecureServerNonceSecret", "SomeDescriptiveRealmName", 30),
                                                    new ExampleUsernameSecretProvider());
            app.UseWebApi(config);
        }
    }
```

This will add a claim of type `DIGEST_AUTHENTICATION_NAME` (value will be the authenticated user name) to the principal on the request context. If you want to simply check for a claim of this type on a controller action, you can use the `DigestAuthorize` attribute

```C#
    public class ValuesController : ApiController
    {
        [DigestAuthorize]
        public string Get() {
            return "Protected info!";
        }
    }
```

If you want something more sophisticated than that, you'll need to roll your own filter.

## More info:
For working examples, check out the AspNetClassicApp & AspNetCoreApp projects in the solution.
