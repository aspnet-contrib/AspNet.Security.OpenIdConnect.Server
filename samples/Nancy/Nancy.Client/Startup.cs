using System;
using System.IdentityModel.Tokens;
using Microsoft.IdentityModel.Protocols;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;
using Owin;

namespace Nancy.Client {
    public class Startup {
        public void Configuration(IAppBuilder app) {
            ConfigureOidcClientDemo(app);
        }

        private static void ConfigureOidcClientDemo(IAppBuilder app) {
            app.SetDefaultSignInAsAuthenticationType("ExternalCookie");

            app.UseCookieAuthentication(new CookieAuthenticationOptions {
                AuthenticationMode = AuthenticationMode.Active,
                AuthenticationType = "ExternalCookie",
                CookieName = CookieAuthenticationDefaults.CookiePrefix + "ExternalCookie",
                ExpireTimeSpan = TimeSpan.FromMinutes(5)
            });

            var key = new InMemorySymmetricSecurityKey(Convert.FromBase64String("Srtjyi8wMFfmP9Ub8U2ieVGAcrP/7gK3VM/K6KfJ/fI="));

            app.UseOpenIdConnectAuthentication(new OpenIdConnectAuthenticationOptions {
                AuthenticationMode = AuthenticationMode.Active,
                AuthenticationType = OpenIdConnectAuthenticationDefaults.AuthenticationType,
                SignInAsAuthenticationType = app.GetDefaultSignInAsAuthenticationType(),
                ClientId = "myClient",
                ClientSecret = "secret_secret_secret",
                RedirectUri = "http://localhost:56765/oidc",
                Scope = "openid",
                Configuration = new OpenIdConnectConfiguration {
                    AuthorizationEndpoint = "http://localhost:55938/oauth2/authorize",
                    TokenEndpoint = "http://localhost:55938/oauth2/access_token"
                },
                TokenValidationParameters = new TokenValidationParameters() {
                    ValidAudience = "myClient",
                    ValidIssuer = "urn:authServer",
                    IssuerSigningKey = key
                }
            });

            app.UseNancy(options => options.PerformPassThrough = context => context.Response.StatusCode == HttpStatusCode.NotFound);
        }
    }
}