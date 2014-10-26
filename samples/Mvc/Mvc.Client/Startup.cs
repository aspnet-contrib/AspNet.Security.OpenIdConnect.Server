using System;
using Microsoft.AspNet.Builder;
using Microsoft.AspNet.Http;
using Microsoft.AspNet.Security;
using Microsoft.AspNet.Security.Cookies;
using Microsoft.AspNet.Security.OAuth;
using Microsoft.Framework.DependencyInjection;

namespace Mvc.Client {
    public class Startup {
        public void Configure(IApplicationBuilder app) {
            app.UseServices(services => {
                services.Configure<ExternalAuthenticationOptions>(options => {
                    options.SignInAsAuthenticationType = "ClientCookie";
                });

                services.AddMvc();
            });

            // Insert a new cookies middleware in the pipeline to store the user
            // identity after he has been redirected from the identity provider.
            app.UseCookieAuthentication(options => {
                options.AuthenticationMode = AuthenticationMode.Active;
                options.AuthenticationType = "ClientCookie";
                options.CookieName = CookieAuthenticationDefaults.CookiePrefix + "ClientCookie";
                options.ExpireTimeSpan = TimeSpan.FromMinutes(5);
            });

            app.UseOAuthAuthentication("OpenIdConnect", options => {
                options.AuthenticationMode = AuthenticationMode.Active;
                options.Notifications = new OAuthAuthenticationNotifications();

                // Note: these settings must match the application
                // details inserted in the database at the server level.
                options.ClientId = "myClient";
                options.ClientSecret = "secret_secret_secret";
                options.CallbackPath = new PathString("/oidc");
                options.AuthorizationEndpoint = "http://localhost:12345/connect/authorize";
                options.TokenEndpoint = "http://localhost:12345/connect/token";

                options.Scope.Add("profile");
            });

            app.UseStaticFiles();

            app.UseMvc();
        }
    }
}