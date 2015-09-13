using System;
using Microsoft.Owin;
using Owin;

namespace Basic.Server {
    public class Startup {
        public void Configuration(IAppBuilder app) {
            app.UseOpenIdConnectServer(options => {
                options.AccessTokenLifetime = TimeSpan.FromDays(14);
                options.IdentityTokenLifetime = TimeSpan.FromMinutes(60);

                options.TokenEndpointPath = new PathString("/token");
                options.AuthorizationEndpointPath = new PathString("/auth.cshtml");

                options.Provider = new AuthorizationProvider();
                options.AllowInsecureHttp = true;
                options.ApplicationCanDisplayErrors = true;
            });
        }
    }
}