using System;
using System.Linq;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Server;
using Microsoft.Data.Entity;
using Microsoft.Framework.DependencyInjection;
using Mvc.Server.Models;

namespace Mvc.Server.Providers {
    public sealed class AuthorizationProvider : OpenIdConnectServerProvider {
        public override async Task ValidateClientAuthentication(ValidateClientAuthenticationNotification notification) {
            if (string.IsNullOrEmpty(notification.ClientId) || string.IsNullOrEmpty(notification.ClientSecret)) {
                notification.SetError(
                    error: "invalid_request",
                    errorDescription: "Missing credentials: ensure that your credentials were correctly " +
                                      "flowed in the request body or in the authorization header");

                return;
            }

            var context = notification.HttpContext.RequestServices.GetRequiredService<ApplicationContext>();

            // Retrieve the application details corresponding to the requested client_id.
            var application = await (from entity in context.Applications
                                     where entity.ApplicationID == notification.ClientId
                                     select entity).SingleOrDefaultAsync(notification.HttpContext.RequestAborted);

            if (application == null) {
                notification.SetError(
                    error: "invalid_client",
                    errorDescription: "Application not found in the database: ensure that your client_id is correct");

                return;
            }

            if (!string.Equals(notification.ClientSecret, application.Secret, StringComparison.Ordinal)) {
                notification.SetError(
                    error: "invalid_client",
                    errorDescription: "Invalid credentials: ensure that you specified a correct client_secret");

                return;
            }

            notification.Validated();
        }

        public override async Task ValidateClientRedirectUri(ValidateClientRedirectUriNotification notification) {
            var context = notification.HttpContext.RequestServices.GetRequiredService<ApplicationContext>();

            // Retrieve the application details corresponding to the requested client_id.
            var application = await (from entity in context.Applications
                                     where entity.ApplicationID == notification.ClientId
                                     select entity).SingleOrDefaultAsync(notification.HttpContext.RequestAborted);

            if (application == null) {
                notification.SetError(
                    error: "invalid_client",
                    errorDescription: "Application not found in the database: ensure that your client_id is correct");

                return;
            }

            if (!string.IsNullOrEmpty(notification.RedirectUri)) {
                if (!string.Equals(notification.RedirectUri, application.RedirectUri, StringComparison.Ordinal)) {
                    notification.SetError(
                        error: "invalid_client",
                        errorDescription: "Invalid redirect_uri");

                    return;
                }
            }

            notification.Validated(application.RedirectUri);
        }

        public override async Task ValidateClientLogoutRedirectUri(ValidateClientLogoutRedirectUriNotification notification) {
            var context = notification.HttpContext.RequestServices.GetRequiredService<ApplicationContext>();

            if (!await context.Applications.AnyAsync(application => application.LogoutRedirectUri == notification.PostLogoutRedirectUri)) {
                notification.SetError(
                    error: "invalid_client",
                    errorDescription: "Invalid post_logout_redirect_uri");

                return;
            }

            notification.Validated();
        }

        public override Task MatchEndpoint(MatchEndpointNotification notification) {
            // Note: by default, OpenIdConnectServerHandler only handles authorization requests made to the authorization endpoint.
            // This notification handler uses a more relaxed policy that allows extracting authorization requests received at
            // /connect/authorize/accept and /connect/authorize/deny (see AuthorizationController.cs for more information).
            if (notification.Request.Path.StartsWithSegments(notification.Options.AuthorizationEndpointPath)) {
                notification.MatchesAuthorizationEndpoint();
            }

            return Task.FromResult<object>(null);
        }
    }
}