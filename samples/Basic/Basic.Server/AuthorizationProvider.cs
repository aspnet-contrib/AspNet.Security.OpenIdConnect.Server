using System;
using System.Threading.Tasks;
using Owin.Security.OpenIdConnect.Server;

namespace Basic.Server {
    public class AuthorizationProvider : OpenIdConnectServerProvider {
        public override Task ValidateClientAuthentication(ValidateClientAuthenticationContext context) {
            if (!string.IsNullOrEmpty(context.ClientId) && !string.IsNullOrEmpty(context.ClientSecret)) {
                if (string.Equals(context.ClientId, "myClient", StringComparison.Ordinal) &&
                    string.Equals(context.ClientSecret, "secret_secret_secret", StringComparison.Ordinal)) {
                    context.Validated();
                }
            }

            return Task.FromResult<object>(null);
        }

        public override Task ValidateClientRedirectUri(ValidateClientRedirectUriContext context) {
            if (context.ClientId == "myClient" && (string.IsNullOrEmpty(context.RedirectUri) || context.RedirectUri == "http://localhost:57264/oidc")) {
                context.Validated("http://localhost:57264/oidc");
            }

            return Task.FromResult<object>(null);
        }
    }
}