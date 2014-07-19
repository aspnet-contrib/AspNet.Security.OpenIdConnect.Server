using Microsoft.Owin;
using SampleOpenIdConnectServer;

[assembly: OwinStartup(typeof(Startup))]

namespace SampleOpenIdConnectServer {
    using System;
    using System.IdentityModel.Tokens;
    using System.Text;
    using Microsoft.Owin;
    using Microsoft.Owin.Security.OpenIdConnect.Server;
    using Owin;

    public class Startup {
        public void Configuration(IAppBuilder app) {
            ConfigureOidcServerDemo(app);
        }

        private static void ConfigureOidcServerDemo(IAppBuilder app) {
            var key = new InMemorySymmetricSecurityKey(Encoding.UTF8.GetBytes("secret_secret_secret"));
            var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256Signature, SecurityAlgorithms.Sha256Digest);

            app.UseOpenIdConnectServer(new OpenIdConnectServerOptions {
                IdTokenExpireTimeSpan = TimeSpan.FromMinutes(60),
                IssuerName = "urn:authServer",
                SigningCredentials = credentials,
                TokenEndpointPath = new PathString("/token"),
                AuthorizeEndpointPath = new PathString("/auth.cshtml"),
                FormPostEndpoint = new PathString("/FormPost.cshtml"),
                Provider = new CustomOpenIdConnectServerProvider(),
                AccessTokenExpireTimeSpan = TimeSpan.FromDays(14),
                AllowInsecureHttp = true,
                ApplicationCanDisplayErrors = true,
                AuthorizationCodeProvider = new TestAuthenticationTokenProvider(),
                RefreshTokenProvider = new TestAuthenticationTokenProvider(),
            });
        }
    }
}