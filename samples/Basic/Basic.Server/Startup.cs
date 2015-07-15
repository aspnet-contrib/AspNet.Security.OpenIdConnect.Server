using System;
using Microsoft.Owin;
using Owin;

namespace Basic.Server {
    public class Startup {
        public void Configuration(IAppBuilder app) {
            app.UseOpenIdConnectServer(options => {
                options.AccessTokenLifetime = TimeSpan.FromDays(14);
                options.IdentityTokenLifetime = TimeSpan.FromMinutes(60);

                // Note: in a real world app, you'd probably prefer storing the X.509 certificate
                // in the user or machine store. To keep this sample easy to use, the certificate
                // is extracted from the Certificate.pfx file embedded in this assembly.
                options.UseCertificate(
                    assembly: typeof(Startup).Assembly,
                    resource: "Basic.Server.Certificate.pfx",
                    password: "Owin.Security.OpenIdConnect.Server");

                options.UseOpaqueTokens();

                options.TokenEndpointPath = new PathString("/token");
                options.AuthorizationEndpointPath = new PathString("/auth.cshtml");

                options.Provider = new AuthorizationProvider();
                options.AllowInsecureHttp = true;
                options.ApplicationCanDisplayErrors = true;
            });
        }
    }
}