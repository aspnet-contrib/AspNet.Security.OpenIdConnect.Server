using System.Threading.Tasks;
using Owin.Security.OpenIdConnect.Server;

namespace Basic.Server {
    public class AuthorizationProvider : OpenIdConnectServerProvider {
        public override Task ValidateClientAuthentication(ValidateClientAuthenticationNotification notification) {
            if (notification.ClientId == null) {
                string clientId, clientSecret;
                notification.TryGetFormCredentials(out clientId, out clientSecret);

                if (clientId == "myClient" && clientSecret == "secret_secret_secret") {
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