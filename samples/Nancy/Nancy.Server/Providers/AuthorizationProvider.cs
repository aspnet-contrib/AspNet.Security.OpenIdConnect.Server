using System;
using System.Data.Entity;
using System.Linq;
using System.Threading.Tasks;
using Nancy.Server.Models;
using Owin.Security.OpenIdConnect.Extensions;
using Owin.Security.OpenIdConnect.Server;

namespace Nancy.Server.Providers {
    public class AuthorizationProvider : OpenIdConnectServerProvider {
        public override async Task ValidateClientAuthentication(ValidateClientAuthenticationContext context) {
            // Note: client authentication is not mandatory for non-confidential client applications like mobile apps
            // (except when using the client credentials grant type) but this authorization server uses a safer policy
            // that makes client authentication mandatory and returns an error if client_id or client_secret is missing.
            // You may consider relaxing it to support the resource owner password credentials grant type
            // with JavaScript or desktop applications, where client credentials cannot be safely stored.
            if (string.IsNullOrEmpty(context.ClientId) || string.IsNullOrEmpty(context.ClientSecret)) {
                context.Rejected(
                    error: "invalid_request",
                    description: "Missing credentials: ensure that your credentials were correctly " +
                                 "flowed in the request body or in the authorization header");

                return;
            }

            using (var database = new ApplicationContext()) {
                // Retrieve the application details corresponding to the requested client_id.
                var application = await (from entity in database.Applications
                                         where entity.ApplicationID == context.ClientId
                                         select entity).SingleOrDefaultAsync(context.OwinContext.Request.CallCancelled);

                if (application == null) {
                    context.Rejected(
                        error: "invalid_client",
                        description: "Application not found in the database: " +
                                     "ensure that your client_id is correct");
                    return;
                }

                if (!string.Equals(context.ClientSecret, application.Secret, StringComparison.Ordinal)) {
                    context.Rejected(
                        error: "invalid_client",
                        description: "Invalid credentials: ensure that you " +
                                     "specified a correct client_secret");

                    return;
                }

                context.Validated();
            }
        }

        public override async Task ValidateClientRedirectUri(ValidateClientRedirectUriContext context) {
            using (var database = new ApplicationContext()) {
                // Retrieve the application details corresponding to the requested client_id.
                var application = await (from entity in database.Applications
                                         where entity.ApplicationID == context.ClientId
                                         select entity).SingleOrDefaultAsync(context.OwinContext.Request.CallCancelled);

                if (application == null) {
                    context.Rejected(
                        error: "invalid_client",
                        description: "Application not found in the database: " +
                                     "ensure that your client_id is correct");
                    return;
                }

                if (!string.IsNullOrEmpty(context.RedirectUri)) {
                    if (!string.Equals(context.RedirectUri, application.RedirectUri, StringComparison.Ordinal)) {
                        context.Rejected(error: "invalid_client", description: "Invalid redirect_uri");

                        return;
                    }
                }

                context.Validated(application.RedirectUri);
            }
        }

        public override async Task ValidateClientLogoutRedirectUri(ValidateClientLogoutRedirectUriContext context) {
            using (var database = new ApplicationContext()) {
                if (!await database.Applications.AnyAsync(application => application.LogoutRedirectUri == context.PostLogoutRedirectUri)) {
                    context.Rejected(error: "invalid_client", description: "Invalid post_logout_redirect_uri");

                    return;
                }

                context.Validated();
            }
        }

        public override Task MatchEndpoint(MatchEndpointContext context) {
            // Note: by default, OpenIdConnectServerHandler only handles authorization requests made to the authorization endpoint.
            // This notification handler uses a more relaxed policy that allows extracting authorization requests received at
            // /connect/authorize/accept and /connect/authorize/deny (see AuthorizationController.cs for more information).
            if (context.Request.Path.StartsWithSegments(context.Options.AuthorizationEndpointPath)) {
                context.MatchesAuthorizationEndpoint();
            }

            return Task.FromResult<object>(null);
        }

        public override Task ValidateTokenRequest(ValidateTokenRequestContext context) {
            // Note: OpenIdConnectServerHandler supports authorization code, refresh token, client credentials
            // and resource owner password credentials grant types but this authorization server uses a safer policy
            // rejecting the last two ones. You may consider relaxing it to support the ROPC or client credentials grant types.
            if (context.Request.IsAuthorizationCodeGrantType() || context.Request.IsRefreshTokenGrantType()) {
                context.Validated();

                return Task.FromResult<object>(null);
            }

            context.Rejected(
                error: "unsupported_grant_type",
                description: "Only authorization code and refresh token grant types " +
                             "are accepted by this authorization server");

            return Task.FromResult<object>(null);
        }
    }
}