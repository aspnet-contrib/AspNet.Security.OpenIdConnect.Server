using Microsoft.Owin;
using SampleOpenIdConnectClient;

[assembly: OwinStartup(typeof(Startup))]

namespace SampleOpenIdConnectClient {
    using System;
    using System.IdentityModel.Tokens;
    using System.Text;
    using Microsoft.IdentityModel.Protocols;
    using Microsoft.Owin.Security;
    using Microsoft.Owin.Security.Cookies;
    using Microsoft.Owin.Security.OpenIdConnect;
    using Owin;

    public class Startup {
        public void Configuration(IAppBuilder app) {
            ConfigureOidcClientDemo(app);
        }

        private static void ConfigureOidcClientDemo(IAppBuilder app) {
            app.SetDefaultSignInAsAuthenticationType("ExternalCookie");

            app.UseCookieAuthentication(new CookieAuthenticationOptions {
                AuthenticationMode = AuthenticationMode.Passive,
                AuthenticationType = "ExternalCookie",
                CookieName = CookieAuthenticationDefaults.CookiePrefix + "ExternalCookie",
                ExpireTimeSpan = TimeSpan.FromMinutes(5)
            });

            var key = new InMemorySymmetricSecurityKey(Encoding.UTF8.GetBytes("secret_secret_secret"));

            app.UseOpenIdConnectAuthentication(new OpenIdConnectAuthenticationOptions {
                AuthenticationMode = AuthenticationMode.Active,
                AuthenticationType = "OIDC",
                SignInAsAuthenticationType = app.GetDefaultSignInAsAuthenticationType(),
                ClientId = "myClient",
                ClientSecret = "secret_secret_secret",
                RedirectUri = "http://localhost:57264/oidc",
                Scope = "openid",
                Configuration = new OpenIdConnectConfiguration {
                    AuthorizationEndpoint = "http://localhost:59504/auth.cshtml",
                    TokenEndpoint = "http://localhost:59504/token"
                },
                TokenValidationParameters = new TokenValidationParameters() {
                    ValidAudience = "myClient",
                    ValidIssuer = "urn:authServer",
                    IssuerSigningKey = key
                }
            });
        }
    }
}