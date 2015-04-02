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
            string clientId, clientSecret;

            // Retrieve the client credentials from the request body.
            // Note: you can also retrieve them from the Authorization
            // header (basic authentication) using TryGetBasicCredentials.
            if (!notification.TryGetFormCredentials(out clientId, out clientSecret) ||
                string.IsNullOrWhiteSpace(clientId) || string.IsNullOrWhiteSpace(clientSecret)) {
                notification.SetError(
                    error: "invalid_request",
                    errorDescription: "Missing credentials: ensure that your credentials " +
                                      "were correctly flowed in the request body");

                return;
            }

            var database = notification.HttpContext.RequestServices.GetRequiredService<ApplicationContext>();

            // Retrieve the application details corresponding to the requested client_id.
            var application = await (from entity in database.Applications
                                     where entity.ApplicationID == clientId
                                     select entity).SingleOrDefaultAsync(notification.HttpContext.RequestAborted);

            if (application == null) {
                notification.SetError(
                    error: "invalid_client",
                    errorDescription: "Application not found in the database: ensure that your client_id is correct");

                return;
            }

            if (!string.Equals(clientSecret, application.Secret, StringComparison.Ordinal)) {
                notification.SetError(
                    error: "invalid_client",
                    errorDescription: "Invalid credentials: ensure that you specified a correct client_secret");

                return;
            }

            notification.Validated(clientId);
        }

        public override async Task ValidateClientRedirectUri(ValidateClientRedirectUriNotification notification) {
            var database = notification.HttpContext.RequestServices.GetRequiredService<ApplicationContext>();

            // Retrieve the application details corresponding to the requested client_id.
            var application = await (from entity in database.Applications
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
    }
}