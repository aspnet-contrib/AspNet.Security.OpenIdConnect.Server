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
using Owin;
using Microsoft.Owin.Security.OpenIdConnect.Server;
using SampleOpenIdConnectServer;
using System.IdentityModel.Tokens;

[assembly: OwinStartup(typeof(Startup))]

namespace SampleOpenIdConnectServer {
    public class Startup {
        public void Configuration(IAppBuilder app) {
            ConfigureOidcServerDemo(app);
        }

        private static void ConfigureOidcServerDemo(IAppBuilder app) {
            // To test the OIDC-Server start the app and use something like fiddler to access 
            // http://localhost:59504/auth.cshtml?response_type=code+id_token&client_id=myClient&state=xyz&redirect_uri=http%3A%2F%2Flocalhost%3A6980%2Foidc&nonce=1234&scope=openid&response_mode=form_post
            // You should get back an id_token using post to the url that is included in this call.
            var key = new InMemorySymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes("secret_secret_secret"));

            app.UseOpenIdConnectAuthorizationServer(new OpenIdConnectServerOptions {
                IdTokenExpireTimeSpan = TimeSpan.FromMinutes(60),
                IssuerName = "urn:authServer",
                SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256Signature, SecurityAlgorithms.Sha256Digest),
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