using System;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace Mvc.Client {
    public class Startup {
        public static void Main(string[] args) {
            var application = new WebHostBuilder()
                .UseDefaultConfiguration(args)
                .UseIISPlatformHandlerUrl()
                .UseServer("Microsoft.AspNetCore.Server.Kestrel")
                .UseStartup<Startup>()
                .Build();

            application.Run();
        }

        public void ConfigureServices(IServiceCollection services) {
            services.AddAuthentication(options => {
                options.SignInScheme = "ClientCookie";
            });

            services.AddMvc();
            services.AddMvcDnx();
        }

        public void Configure(IApplicationBuilder app, ILoggerFactory factory) {
            factory.AddConsole();
            factory.AddDebug();

            app.UseDeveloperExceptionPage();

            // Insert a new cookies middleware in the pipeline to store the user
            // identity after he has been redirected from the identity provider.
            app.UseCookieAuthentication(new CookieAuthenticationOptions {
                AutomaticAuthenticate = true,
                AutomaticChallenge = true,
                AuthenticationScheme = "ClientCookie",
                CookieName = CookieAuthenticationDefaults.CookiePrefix + "ClientCookie",
                ExpireTimeSpan = TimeSpan.FromMinutes(5),
                LoginPath = new PathString("/signin")
            });

            app.UseOpenIdConnectAuthentication(new OpenIdConnectOptions {
                AuthenticationScheme = OpenIdConnectDefaults.AuthenticationScheme,
                RequireHttpsMetadata = false,
                SaveTokens = true,

                // Note: these settings must match the application details
                // inserted in the database at the server level.
                ClientId = "myClient",
                ClientSecret = "secret_secret_secret",
                PostLogoutRedirectUri = "http://localhost:53507/",

                // Use the authorization code flow.
                ResponseType = OpenIdConnectResponseTypes.Code,

                // Note: setting the Authority allows the OIDC client middleware to automatically
                // retrieve the identity provider's configuration and spare you from setting
                // the different endpoints URIs or the token validation parameters explicitly.
                Authority = "http://localhost:54540/"
            });

            app.UseStaticFiles();

            app.UseMvc();
        }
    }
}