/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Extensions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http.Features.Authentication;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.Net.Http.Headers;

namespace AspNet.Security.OpenIdConnect.Server {
    internal partial class OpenIdConnectServerHandler : AuthenticationHandler<OpenIdConnectServerOptions> {
        private async Task<bool> InvokeLogoutEndpointAsync() {
            OpenIdConnectMessage request = null;

            // Note: logout requests must be made via GET but POST requests
            // are also accepted to allow flowing large logout payloads.
            // See https://openid.net/specs/openid-connect-session-1_0.html#RPLogout
            if (string.Equals(Request.Method, "GET", StringComparison.OrdinalIgnoreCase)) {
                request = new OpenIdConnectMessage(Request.Query.ToDictionary()) {
                    RequestType = OpenIdConnectRequestType.LogoutRequest
                };
            }

            else if (string.Equals(Request.Method, "POST", StringComparison.OrdinalIgnoreCase)) {
                // See http://openid.net/specs/openid-connect-core-1_0.html#FormSerialization
                if (string.IsNullOrEmpty(Request.ContentType)) {
                    return await SendErrorPageAsync(new OpenIdConnectMessage {
                        Error = OpenIdConnectConstants.Errors.InvalidRequest,
                        ErrorDescription = "A malformed logout request has been received: " +
                            "the mandatory 'Content-Type' header was missing from the POST request."
                    });
                }

                // May have media/type; charset=utf-8, allow partial match.
                if (!Request.ContentType.StartsWith("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase)) {
                    return await SendErrorPageAsync(new OpenIdConnectMessage {
                        Error = OpenIdConnectConstants.Errors.InvalidRequest,
                        ErrorDescription = "A malformed logout request has been received: " +
                            "the 'Content-Type' header contained an unexcepted value. " +
                            "Make sure to use 'application/x-www-form-urlencoded'."
                    });
                }

                var form = await Request.ReadFormAsync(Context.RequestAborted);

                request = new OpenIdConnectMessage(form.ToDictionary()) {
                    RequestType = OpenIdConnectRequestType.LogoutRequest
                };
            }

            else {
                Logger.LogInformation("A malformed request has been received by the logout endpoint.");

                return await SendErrorPageAsync(new OpenIdConnectMessage {
                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = "A malformed logout request has been received: " +
                                       "make sure to use either GET or POST."
                });
            }

            // Store the logout request in the ASP.NET context.
            Context.SetOpenIdConnectRequest(request);

            var validatingContext = new ValidateLogoutRequestContext(Context, Options, request);
            await Options.Provider.ValidateLogoutRequest(validatingContext);

            if (validatingContext.IsRejected) {
                Logger.LogError("The logout request was rejected.");

                return await SendErrorPageAsync(new OpenIdConnectMessage {
                    Error = validatingContext.Error,
                    ErrorDescription = validatingContext.ErrorDescription,
                    ErrorUri = validatingContext.ErrorUri
                });
            }

            var notification = new LogoutEndpointContext(Context, Options, request);
            await Options.Provider.LogoutEndpoint(notification);

            if (notification.HandledResponse) {
                return true;
            }

            return false;
        }

        protected override async Task HandleSignOutAsync(SignOutContext context) {
            // request may be null when no logout request has been received
            // or has been already handled by InvokeLogoutEndpointAsync.
            var request = Context.GetOpenIdConnectRequest();
            if (request == null) {
                return;
            }

            // Stop processing the request if there's no signout context that matches
            // the authentication type associated with this middleware instance
            // or if the response status code doesn't indicate a successful response.
            if (context == null || Response.StatusCode != 200) {
                return;
            }

            if (Response.HasStarted) {
                Logger.LogCritical(
                    "OpenIdConnectServerHandler.TeardownCoreAsync cannot be called when " +
                    "the response headers have already been sent back to the user agent. " +
                    "Make sure the response body has not been altered and that no middleware " +
                    "has attempted to write to the response stream during this request.");
                return;
            }

            // post_logout_redirect_uri is added to the response message since it can be
            // set or replaced from the ValidateClientLogoutRedirectUri event.
            var response = new OpenIdConnectMessage {
                PostLogoutRedirectUri = request.PostLogoutRedirectUri,
                State = request.State
            };

            var notification = new LogoutEndpointResponseContext(Context, Options, request, response);
            await Options.Provider.LogoutEndpointResponse(notification);

            if (notification.HandledResponse) {
                return;
            }

            // Stop processing the request if no explicit
            // post_logout_redirect_uri has been provided.
            if (string.IsNullOrEmpty(response.PostLogoutRedirectUri)) {
                return;
            }

            var location = response.PostLogoutRedirectUri;

            foreach (var parameter in response.Parameters) {
                // Don't include post_logout_redirect_uri in the query string.
                if (string.Equals(parameter.Key, OpenIdConnectParameterNames.PostLogoutRedirectUri, StringComparison.Ordinal)) {
                    continue;
                }

                location = QueryHelpers.AddQueryString(location, parameter.Key, parameter.Value);
            }

            Response.Redirect(location);
        }

        protected override async Task<bool> HandleUnauthorizedAsync(ChallengeContext context) {
            var notification = new MatchEndpointContext(Context, Options);

            if (Options.ProfileEndpointPath.HasValue &&
                Options.ProfileEndpointPath == Request.Path) {
                notification.MatchesProfileEndpoint();
            }

            await Options.Provider.MatchEndpoint(notification);

            // Return true to indicate to the authentication pipeline that
            // the 401 response shouldn't be handled by the other middleware.
            if (!notification.IsProfileEndpoint) {
                return true;
            }

            Response.StatusCode = 401;
            Response.Headers[HeaderNames.WWWAuthenticate] = "error=" + OpenIdConnectConstants.Errors.InvalidGrant;

            return false;
        }
    }
}