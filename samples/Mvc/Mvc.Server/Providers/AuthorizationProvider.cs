using System;
using System.Data.Entity;
using System.Linq;
using System.Threading.Tasks;
using Mvc.Server.Models;
using Owin.Security.OpenIdConnect.Server;

namespace Mvc.Server.Providers {
    public class AuthorizationProvider : OpenIdConnectServerProvider {
        public override async Task ValidateClientAuthentication(ValidateClientAuthenticationNotification notification) {
            string clientId, clientSecret;

            // Retrieve the client credentials from the request body.
            // Note: you can also retrieve them from the Authorization
            // header (basic authentication) using TryGetBasicCredentials.
            notification.TryGetFormCredentials(out clientId, out clientSecret);

            if (string.IsNullOrEmpty(clientId) || string.IsNullOrEmpty(clientSecret)) {
                notification.SetError(
                    error: "invalid_request",
                    errorDescription: "Missing credentials: ensure that your credentials " +
                                      "were correctly flowed in the request body");

                return;
            }

            using (var context = new ApplicationContext()) {
                // Retrieve the application details corresponding to the requested client_id.
                var application = await (from entity in context.Applications
                                         where entity.ApplicationID == clientId
                                         select entity).SingleOrDefaultAsync(notification.Request.CallCancelled);

                if (application == null) {
                    notification.SetError(
                        error: "invalid_client",
                        errorDescription: "Application not found in the database: " +
                                          "ensure that your client_id is correct");
                    return;
                }

                if (!string.Equals(clientSecret, application.Secret, StringComparison.Ordinal)) {
                    notification.SetError(
                        error: "invalid_client",
                        errorDescription: "Invalid credentials: ensure that you " +
                                          "specified a correct client_secret");

                    return;
                }

                notification.Validated(clientId);
            }
        }

        public override async Task ValidateClientRedirectUri(ValidateClientRedirectUriNotification notification) {
            using (var context = new ApplicationContext()) {
                // Retrieve the application details corresponding to the requested client_id.
                var application = await (from entity in context.Applications
                                         where entity.ApplicationID == notification.ClientId
                                         select entity).SingleOrDefaultAsync(notification.Request.CallCancelled);

                if (application == null) {
                    notification.SetError(
                        error: "invalid_client",
                        errorDescription: "Application not found in the database: " +
                                          "ensure that your client_id is correct");
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

        public override async Task ValidateClientLogoutRedirectUri(ValidateClientLogoutRedirectUriNotification notification) {
            using (var context = new ApplicationContext()) {
                if (!await context.Applications.AnyAsync(application => application.LogoutRedirectUri == notification.PostLogoutRedirectUri)) {
                    notification.SetError(
                            error: "invalid_client",
                            errorDescription: "Invalid post_logout_redirect_uri");

                    return;
                }

                notification.Validated();
            }
        }

        public override async Task CreateAuthorizationCode(CreateAuthorizationCodeNotification notification) {
            using (var context = new ApplicationContext()) {
                // Create a new unique identifier that will be used to replace the authorization code serialized
                // by CreateAuthorizationCodeNotification.SerializeTicket() during the code/token exchange process.
                // Note: while you can replace the generation mechanism, you MUST ensure your custom algorithm
                // generates unpredictable identifiers to guarantee a correct entropy.

                string nonceID = Guid.NewGuid().ToString();

                var nonce = new Nonce {
                    NonceID = nonceID,
                    Ticket = notification.SerializeTicket()
                };

                context.Nonces.Add(nonce);
                await context.SaveChangesAsync(notification.Request.CallCancelled);

                notification.AuthorizationCode = nonceID;
            }
        }

        public override async Task ReceiveAuthorizationCode(ReceiveAuthorizationCodeNotification notification) {
            using (var context = new ApplicationContext()) {
                // Retrieve the authorization code serialized by CreateAuthorizationCodeNotification.SerializeTicket
                // using the nonce identifier generated in CreateAuthorizationCode and returned to the client application.
                // Note: you MUST ensure the nonces are correctly removed after each call to prevent replay attacks.
                string nonceID = notification.AuthorizationCode;

                var nonce = await (from entity in context.Nonces
                                   where entity.NonceID == nonceID
                                   select entity).SingleOrDefaultAsync(notification.Request.CallCancelled);

                if (nonce == null) {
                    return;
                }

                context.Nonces.Remove(nonce);
                await context.SaveChangesAsync(notification.Request.CallCancelled);

                notification.AuthenticationTicket = notification.DeserializeTicket(nonce.Ticket);
            }
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