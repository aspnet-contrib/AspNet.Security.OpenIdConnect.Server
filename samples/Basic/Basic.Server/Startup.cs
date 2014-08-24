using System;
using System.IdentityModel.Tokens;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Owin;
using Owin;
using Owin.Security.OpenIdConnect.Server;

namespace Basic.Server {
    public class Startup {
        public void Configuration(IAppBuilder app) {
            byte[] content;

            // Note: in a real world app, you'd probably prefer storing the X.509 certificate
            // in the user or machine store. To keep this sample easy to use, the certificate
            // is extracted from the Certificate.pfx file embedded in this assembly.
            using (var stream = typeof(Startup).Assembly.GetManifestResourceStream("Basic.Server.Certificate.pfx"))
            using (var memory = new MemoryStream()) {
                stream.CopyTo(memory);
                memory.Flush();
                content = memory.ToArray();
            }

            var certificate = new X509Certificate2(content, password: "Owin.Security.OpenIdConnect.Server");
            var credentials = new X509SigningCredentials(certificate);

            app.UseOpenIdConnectServer(new OpenIdConnectServerOptions {
                IdTokenExpireTimeSpan = TimeSpan.FromMinutes(60),
                Issuer = "http://localhost:59504/",
                SigningCredentials = credentials,
                TokenEndpointPath = new PathString("/token"),
                AuthorizationEndpointPath = new PathString("/auth.cshtml"),
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