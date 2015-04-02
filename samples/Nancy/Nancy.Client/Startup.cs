using System;
using System.Threading.Tasks;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;
using Owin;

namespace Nancy.Client {
    public class Startup {
        public void Configuration(IAppBuilder app) {
            app.SetDefaultSignInAsAuthenticationType("ClientCookie");

            // Insert a new cookies middleware in the pipeline to store the user
            // identity after he has been redirected from the identity provider.
            app.UseCookieAuthentication(new CookieAuthenticationOptions {
                AuthenticationMode = AuthenticationMode.Active,
                AuthenticationType = "ClientCookie",
                CookieName = CookieAuthenticationDefaults.CookiePrefix + "ClientCookie",
                ExpireTimeSpan = TimeSpan.FromMinutes(5)
            });

            // Insert a new OIDC client middleware in the pipeline.
            app.UseOpenIdConnectAuthentication(new OpenIdConnectAuthenticationOptions {
                AuthenticationMode = AuthenticationMode.Active,
                AuthenticationType = OpenIdConnectAuthenticationDefaults.AuthenticationType,
                SignInAsAuthenticationType = app.GetDefaultSignInAsAuthenticationType(),

                // Note: these settings must match the application details inserted in
                // the database at the server level (see ApplicationContextInitializer.cs).
                ClientId = "myClient",
                ClientSecret = "secret_secret_secret",
                RedirectUri = "http://localhost:56765/oidc",
                
                // Note: setting the Authority allows the OIDC client middleware to automatically
                // retrieve the identity provider's configuration and spare you from setting
                // the different endpoints URIs or the token validation parameters explicitly.
                Authority = "http://localhost:54541/",

                // Note: by default, the OIDC client throws an OpenIdConnectProtocolException
                // when an error occurred during the authentication/authorization process.
                // To prevent a YSOD from being displayed, the response is declared as handled.
                Notifications = new OpenIdConnectAuthenticationNotifications {
                    AuthenticationFailed = notification => {
                        if (string.Equals(notification.ProtocolMessage.Error, "access_denied", StringComparison.Ordinal)) {
                            notification.HandleResponse();

                            notification.Response.Redirect("/");
                        }

                        return Task.FromResult<object>(null);
                    }
                }
            });

            app.UseNancy(options => options.PerformPassThrough = context => context.Response.StatusCode == HttpStatusCode.NotFound);
        }
    }
}