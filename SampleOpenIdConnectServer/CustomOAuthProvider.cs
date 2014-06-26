using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Owin.Security.OAuth;

namespace SampleOpenIdConnectServer
{
    class CustomOAuthProvider : OAuthAuthorizationServerProvider
    {
        public override Task ValidateClientAuthentication(OAuthValidateClientAuthenticationContext context)
        {

            if (context.ClientId == null)
            {
                string clientId, clientSecret;
                context.TryGetFormCredentials(out clientId, out clientSecret);

                if (clientId == "myClient" && clientSecret == "secret_secret_secret")
                {
                    context.Validated();
                }

            }

            return Task.FromResult<object>(null);

        }

        public override Task ValidateClientRedirectUri(OAuthValidateClientRedirectUriContext context)
        {
            if (context.ClientId == "myClient" &&
                            context.RedirectUri == "http://localhost:6980/oidc")
            {
                context.Validated();
            }

            return Task.FromResult<object>(null);
        }

    }
}
