using System;
using System.IdentityModel.Tokens;
using Microsoft.Owin;
using Owin;
using Owin.Security.OpenIdConnect.Server;

namespace Basic.Server {
    public class Startup {
        public void Configuration(IAppBuilder app) {
            ConfigureOidcServerDemo(app);
        }

        private static void ConfigureOidcServerDemo(IAppBuilder app) {
            // You can easily generate a new base64-encoded key using RNGCryptoServiceProvider:
            //using (var generator = new RNGCryptoServiceProvider()) {
            //    var buffer = new byte[256 / 8];
            //    generator.GetBytes(buffer);
            //    Console.WriteLine(Convert.ToBase64String(buffer));
            //}

            var key = new InMemorySymmetricSecurityKey(Convert.FromBase64String("Srtjyi8wMFfmP9Ub8U2ieVGAcrP/7gK3VM/K6KfJ/fI="));
            var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256Signature, SecurityAlgorithms.Sha256Digest);

            app.UseOpenIdConnectServer(new OpenIdConnectServerOptions {
                IdTokenExpireTimeSpan = TimeSpan.FromMinutes(60),
                IssuerName = "urn:authServer",
                SigningCredentials = credentials,
                TokenEndpointPath = new PathString("/token"),
                AuthorizeEndpointPath = new PathString("/auth.cshtml"),
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