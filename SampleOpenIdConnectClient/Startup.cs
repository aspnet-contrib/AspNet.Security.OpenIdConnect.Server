using System;
using System.Collections.Concurrent;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;
using System.Threading.Tasks;
using Microsoft.Owin;
using Microsoft.Owin.Extensions;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Owin;
using System.IdentityModel.Tokens;
using Microsoft.Owin.Security.OpenIdConnect;
using Microsoft.IdentityModel.Protocols;
using SampleOpenIdConnectClient;
using Microsoft.Owin.Security.Cookies;

[assembly: OwinStartup(typeof(Startup))]

namespace SampleOpenIdConnectClient {
    public class Startup {
        public void Configuration(IAppBuilder app) {
            ConfigureOidcClientDemo(app);
        }

        private static void ConfigureOidcClientDemo(IAppBuilder app) {
            app.UseExternalSignInCookie("ExternalCookie");

            var key = new InMemorySymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes("secret_secret_secret"));

            app.UseOpenIdConnectAuthentication(new OpenIdConnectAuthenticationOptions {
                AuthenticationMode = AuthenticationMode.Active,
                AuthenticationType = "OIDC",
                SignInAsAuthenticationType = "ExternalCookie",
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