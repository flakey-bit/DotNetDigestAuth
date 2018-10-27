# DotNetDigestAuth
Implementation of Digest Authentication for ASP.NET Core (AuthenticationHandler) &amp; ASP.NET (OWIN Middleware).

Supports: ASP.NET running on .NET Framework 4.6.1+ or ASP.NET Core running on .NET Standard 2.0+ 

## Usage in ASP.NET Core:

- You'll want to reference the NuGet package `FlakeyBit.DigestAuthentication.AspNetCore`.
- You'll need both of the following references:

```C#
using FlakeyBit.DigestAuthentication.AspNetCore;
using FlakeyBit.DigestAuthentication.Implementation;
```

Then, you'll need to provide an implementation of IUsernameSecretProvider - a trivial example is given below:

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

In your web host startup:

```C#
public class Startup
{
        public void ConfigureServices(IServiceCollection services) {
            services.AddAuthentication("Digest")
                    .AddDigestAuthentication(DigestAuthenticationConfiguration.Create("VerySecret", "some-realm", 30),
                                             new ExampleUsernameSecretProvider());
            services.AddMvc();
        }
}
```

(See DigestAuthenticationConfiguration.Create) for more details

Finally, add the `Authorize` attribute to your controller actions as follows:
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

### DigestAuthenticationConfiguration.Create:
The values `VerySecret` (server nonce secret) and `SomeRealm` (realm name) should be replaced as appropriate. The server nonce secret


