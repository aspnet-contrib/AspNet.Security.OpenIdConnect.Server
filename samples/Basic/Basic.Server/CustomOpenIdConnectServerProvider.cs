using System.Threading.Tasks;
using Owin.Security.OpenIdConnect.Server;

namespace Basic.Server {
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
            if (context.ClientId == "myClient" && (string.IsNullOrEmpty(context.RedirectUri) || context.RedirectUri == "http://localhost:57264/oidc")) {
                context.Validated("http://localhost:57264/oidc");
            }

            return Task.FromResult<object>(null);
        }
    }
}