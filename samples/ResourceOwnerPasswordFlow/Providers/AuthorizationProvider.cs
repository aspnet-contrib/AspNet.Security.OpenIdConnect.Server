

using System;
using System.Linq;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Server;
using AspNet.Security.OpenIdConnect.Extensions;
using Microsoft.Framework.DependencyInjection;
using System.Security.Claims;

namespace ResourceOwnerPasswordFlow.Providers
{
    public sealed class AuthorizationProvider : OpenIdConnectServerProvider
    {
        public override Task ValidateClientAuthentication(
            ValidateClientAuthenticationNotification notification)
        {
            // 
            // TODO Validate the client app
            // if valid, then...

            notification.Validated();
            return Task.FromResult<object>(null);
        }

        public override Task GrantResourceOwnerCredentials(
            GrantResourceOwnerCredentialsNotification notification)
        {
            //
            // TODO check the username and password
            // if valid, then...
            //

            var identity = new ClaimsIdentity(OpenIdConnectDefaults.AuthenticationScheme);

            // this automatically goes into the token and id_token
            identity.AddClaim(ClaimTypes.NameIdentifier, "TODO: Add an appropriate name identifier.");

            // the other claims require explicit destinations
            identity.AddClaim(ClaimTypes.Name, "John", "token id_token");
            identity.AddClaim(ClaimTypes.Surname, "Doe", "token id_token");

            var principal = new ClaimsPrincipal(identity);
            notification.Validated(principal);

            return Task.FromResult<object>(null);
        }
    }
}