using FlakeyBit.DigestAuthentication.AspNetCore;
using FlakeyBit.DigestAuthentication.Implementation;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace AspNetCoreApp
{
    public class Startup
    {
        public Startup(IConfiguration configuration) {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services) {
            // Example configuration providing an IUsernameSecretProvider (which returns the secret for a given username in plaintext)
            // services.AddScoped<IUsernameSecretProvider, TrivialUsernameSecretProvider>();
            // services.AddAuthentication("Digest")
            //         .AddDigestAuthentication(DigestAuthenticationConfiguration.Create("VerySecret", "some-realm", 60, true, 20));

            // Example configuration using IUsernameHashedSecretProvider (which returns the pre-computed MD5 hash of the secret "A1")
            services.AddScoped<IUsernameHashedSecretProvider, TrivialUsernameHashedSecretProvider>();
            services.AddAuthentication("Digest")
                    .AddDigestAuthentication(DigestAuthenticationConfiguration.Create("VerySecret", "some-realm", 60, true, 20));

            services.AddMvc();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env) {
            if (env.IsDevelopment()) {
                app.UseDeveloperExceptionPage();
            }

            app.UseMvc();
        }
    }
}