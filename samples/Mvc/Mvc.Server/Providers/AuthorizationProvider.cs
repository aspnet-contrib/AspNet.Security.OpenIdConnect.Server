using System;
using System.Data.Entity;
using System.Linq;
using System.Threading.Tasks;
using Mvc.Server.Models;
using Owin.Security.OpenIdConnect.Extensions;
using Owin.Security.OpenIdConnect.Server;

namespace Mvc.Server.Providers {
    public class AuthorizationProvider : OpenIdConnectServerProvider {
        public override async Task ValidateClientAuthentication(ValidateClientAuthenticationNotification notification) {
            // Note: client authentication is not mandatory for non-confidential client applications like mobile apps
            // (except when using the client credentials grant type) but this authorization server uses a safer policy
            // that makes client authentication mandatory and returns an error if client_id or client_secret is missing.
            // You may consider relaxing it to support the resource owner password credentials grant type
            // with JavaScript or desktop applications, where client credentials cannot be safely stored.
            if (string.IsNullOrEmpty(notification.ClientId) || string.IsNullOrEmpty(notification.ClientSecret)) {
                notification.Rejected(
                    error: "invalid_request",
                    description: "Missing credentials: ensure that your credentials were correctly " +
                                 "flowed in the request body or in the authorization header");

                return;
            }

            using (var context = new ApplicationContext()) {
                // Retrieve the application details corresponding to the requested client_id.
                var application = await (from entity in context.Applications
                                         where entity.ApplicationID == notification.ClientId
                                         select entity).SingleOrDefaultAsync(notification.OwinContext.Request.CallCancelled);

                if (application == null) {
                    notification.Rejected(
                        error: "invalid_client",
                        description: "Application not found in the database: " +
                                     "ensure that your client_id is correct");
                    return;
                }

                if (!string.Equals(notification.ClientSecret, application.Secret, StringComparison.Ordinal)) {
                    notification.Rejected(
                        error: "invalid_client",
                        description: "Invalid credentials: ensure that you " +
                                     "specified a correct client_secret");

                    return;
                }

                notification.Validated();
            }
        }

        public override async Task ValidateClientRedirectUri(ValidateClientRedirectUriNotification notification) {
            using (var context = new ApplicationContext()) {
                // Retrieve the application details corresponding to the requested client_id.
                var application = await (from entity in context.Applications
                                         where entity.ApplicationID == notification.ClientId
                                         select entity).SingleOrDefaultAsync(notification.OwinContext.Request.CallCancelled);

                if (application == null) {
                    notification.Rejected(
                        error: "invalid_client",
                        description: "Application not found in the database: " +
                                     "ensure that your client_id is correct");
                    return;
                }

                if (!string.IsNullOrEmpty(notification.RedirectUri)) {
                    if (!string.Equals(notification.RedirectUri, application.RedirectUri, StringComparison.Ordinal)) {
                        notification.Rejected(error: "invalid_client", description: "Invalid redirect_uri");

                        return;
                    }
                }

                notification.Validated(application.RedirectUri);
            }
        }

        public override async Task ValidateClientLogoutRedirectUri(ValidateClientLogoutRedirectUriNotification notification) {
            using (var context = new ApplicationContext()) {
                if (!await context.Applications.AnyAsync(application => application.LogoutRedirectUri == notification.PostLogoutRedirectUri)) {
                    notification.Rejected(error: "invalid_client", description: "Invalid post_logout_redirect_uri");

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
                    Ticket = await notification.SerializeTicketAsync()
                };

                context.Nonces.Add(nonce);
                await context.SaveChangesAsync(notification.OwinContext.Request.CallCancelled);

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
                                   select entity).SingleOrDefaultAsync(notification.OwinContext.Request.CallCancelled);

                if (nonce == null) {
                    return;
                }

                context.Nonces.Remove(nonce);
                await context.SaveChangesAsync(notification.OwinContext.Request.CallCancelled);

                notification.AuthenticationTicket = await notification.DeserializeTicketAsync(nonce.Ticket);
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

        public override Task ValidateTokenRequest(ValidateTokenRequestNotification notification) {
            // Note: OpenIdConnectServerHandler supports authorization code, refresh token, client credentials
            // and resource owner password credentials grant types but this authorization server uses a safer policy
            // rejecting the last two ones. You may consider relaxing it to support the ROPC or client credentials grant types.
            if (notification.Request.IsAuthorizationCodeGrantType() || notification.Request.IsRefreshTokenGrantType()) {
                notification.Validated();

                return Task.FromResult<object>(null);
            }

            notification.Rejected(
                error: "unsupported_grant_type",
                description: "Only authorization code and refresh token grant types " +
                             "are accepted by this authorization server");

            return Task.FromResult<object>(null);
        }
    }
}