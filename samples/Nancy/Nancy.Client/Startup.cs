using System;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;
using Owin;

namespace Nancy.Client {
    public class Startup {
        public void Configuration(IAppBuilder app) {
            app.SetDefaultSignInAsAuthenticationType("ClientCookie");

            // Insert a new cookies middleware in the pipeline to store the user
            // identity after he has been redirect from the identity provider.
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

                Scope = "openid",

                // Note: setting the Authority allows the OIDC client middleware to automatically
                // retrieve the identity provider's configuration and spare you from setting
                // the different endpoints URIs or the token validation parameters explicitly.
                Authority = "http://localhost:55938/"
            });

            app.UseNancy(options => options.PerformPassThrough = context => context.Response.StatusCode == HttpStatusCode.NotFound);
        }
    }
}