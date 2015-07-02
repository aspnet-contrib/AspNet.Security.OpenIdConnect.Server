

using System;
using System.Linq;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Server;
using AspNet.Security.OpenIdConnect.Extensions;
using Microsoft.Framework.DependencyInjection;
using System.Security.Claims;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.AspNet.Hosting;

namespace ResourceOwnerPasswordFlow.Providers
{
    public sealed class AuthorizationProvider : OpenIdConnectServerProvider
    {
        private UserManager<IdentityUser> _userManager;

        public AuthorizationProvider(UserManager<IdentityUser> userManager)
        {
            _userManager = userManager;
        }

        public override Task ValidateClientAuthentication(
            ValidateClientAuthenticationNotification notification)
        {
            // 
            // TODO Validate the client app
            // if valid, then...

            notification.Validated();
            return Task.FromResult<object>(null);
        }

        public async override Task GrantResourceOwnerCredentials(
            GrantResourceOwnerCredentialsNotification notification)
        {
            var username = notification.UserName;
            var password = notification.Password;

            var user = await _userManager.FindByNameAsync(username);
            var isValid = await _userManager.CheckPasswordAsync(user, password);

            if (isValid)
            {
                var identity = new ClaimsIdentity(OpenIdConnectDefaults.AuthenticationScheme);

                // this automatically goes into the token and id_token
                identity.AddClaim(ClaimTypes.NameIdentifier, "TODO: Add an appropriate name identifier.");

                // the other claims require explicit destinations
                identity.AddClaim(ClaimTypes.Name, username, "token id_token");
                identity.AddClaim(ClaimTypes.Surname, "Doe", "token id_token");

                var principal = new ClaimsPrincipal(identity);
                notification.Validated(principal);
            }

            // no return type
            // because it's async now
            // is this appropriate?
        }
    }
}