namespace SampleOpenIdConnectServer {
    using System.Threading.Tasks;
    using Microsoft.Owin.Security.OpenIdConnect.Server;

    class CustomOpenIdConnectServerProvider : OpenIdConnectServerProvider {
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
            if (context.ClientId == "myClient" &&
                            context.RedirectUri == "http://localhost:57264/oidc") {
                context.Validated();
            }

            return Task.FromResult<object>(null);
        }

    }
}