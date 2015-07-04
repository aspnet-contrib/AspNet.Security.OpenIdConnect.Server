using System;
using System.Threading.Tasks;
using Owin.Security.OpenIdConnect.Server;

namespace Basic.Server {
    public class AuthorizationProvider : OpenIdConnectServerProvider {
        public override Task ValidateClientAuthentication(ValidateClientAuthenticationNotification notification) {
            if (!string.IsNullOrEmpty(notification.ClientId) && !string.IsNullOrEmpty(notification.ClientSecret)) {
                if (string.Equals(notification.ClientId, "myClient", StringComparison.Ordinal) &&
                    string.Equals(notification.ClientSecret, "secret_secret_secret", StringComparison.Ordinal)) {
                    notification.Validated();
                }
            }

            return Task.FromResult<object>(null);
        }

        public override Task ValidateClientRedirectUri(ValidateClientRedirectUriNotification notification) {
            if (notification.ClientId == "myClient" && (string.IsNullOrEmpty(notification.RedirectUri) || notification.RedirectUri == "http://localhost:57264/oidc")) {
                notification.Validated("http://localhost:57264/oidc");
            }

            return Task.FromResult<object>(null);
        }
    }
}