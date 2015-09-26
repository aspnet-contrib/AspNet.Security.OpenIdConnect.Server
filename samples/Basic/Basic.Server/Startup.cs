using System.Threading.Tasks;
using Microsoft.Owin;
using Owin;
using Owin.Security.OpenIdConnect.Server;

namespace Basic.Server {
    public class Startup {
        public void Configuration(IAppBuilder app) {
            app.UseOpenIdConnectServer(configuration => {
                // Replace the default authorization endpoint to use auth.cshtml.
                configuration.Options.AuthorizationEndpointPath = new PathString("/auth.cshtml");

                // Turn AllowInsecureHttp to avoid rejected non-HTTPS requests.
                configuration.Options.AllowInsecureHttp = true;

                // Set up an inline provider to control the OpenID Connect server.
                configuration.Provider = new OpenIdConnectServerProvider {
                    OnValidateClientRedirectUri = context => {
                        if (context.ClientId == "myClient" && (string.IsNullOrEmpty(context.RedirectUri) ||
                                                               context.RedirectUri == "http://localhost:57264/oidc")) {
                            context.Validated("http://localhost:57264/oidc");
                        }

                        return Task.FromResult<object>(null);
                    }
                };
            });
        }
    }
}