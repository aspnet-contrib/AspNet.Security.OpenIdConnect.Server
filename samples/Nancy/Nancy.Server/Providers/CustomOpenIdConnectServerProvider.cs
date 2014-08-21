using System.Threading.Tasks;
using Owin.Security.OpenIdConnect.Server;

namespace Nancy.Server.Providers {
    public class CustomOpenIdConnectServerProvider : OpenIdConnectServerProvider {
        public override Task ValidateClientAuthentication(OpenIdConnectValidateClientAuthenticationContext context) {
            if (context.ClientId == null) {
                string clientId, clientSecret;
                context.TryGetFormCredentials(out clientId, out clientSecret);

                if (clientId == "myClient" && clientSecret == "secret_secret_secret") {
                    context.Validated();
                }
            }

            return Task.FromResult<object>(null);
        }

        public override Task ValidateClientRedirectUri(OpenIdConnectValidateClientRedirectUriContext context) {
            if (context.ClientId == "myClient" && context.RedirectUri == "http://localhost:56765/oidc") {
                context.Validated();
            }

            return Task.FromResult<object>(null);
        }
    }
}