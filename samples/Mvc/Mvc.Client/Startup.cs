using System;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace Mvc.Client {
    public class Startup {
        public void ConfigureServices(IServiceCollection services) {
            services.AddAuthentication(options => {
                options.SignInScheme = "ClientCookie";
            });

            services.AddMvc();
        }

        public void Configure(IApplicationBuilder app) {
            app.UseDeveloperExceptionPage();

            // Insert a new cookies middleware in the pipeline to store the user
            // identity after he has been redirected from the identity provider.
            app.UseCookieAuthentication(new CookieAuthenticationOptions {
                AutomaticAuthenticate = true,
                AutomaticChallenge = true,
                AuthenticationScheme = "ClientCookie",
                CookieName = CookieAuthenticationDefaults.CookiePrefix + "ClientCookie",
                ExpireTimeSpan = TimeSpan.FromMinutes(5),
                LoginPath = new PathString("/signin"),
                LogoutPath = new PathString("/signout")
            });

            app.UseOpenIdConnectAuthentication(new OpenIdConnectOptions {
                RequireHttpsMetadata = false,
                SaveTokens = true,

                // Note: these settings must match the application details
                // inserted in the database at the server level.
                ClientId = "myClient",
                ClientSecret = "secret_secret_secret",
                PostLogoutRedirectUri = "http://localhost:53507/",

                // Use the authorization code flow.
                ResponseType = OpenIdConnectResponseType.Code,

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
