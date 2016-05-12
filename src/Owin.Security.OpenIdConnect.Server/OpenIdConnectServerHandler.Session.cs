/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Protocols;
using Microsoft.Owin.Infrastructure;
using Microsoft.Owin.Security.Infrastructure;
using Owin.Security.OpenIdConnect.Extensions;

namespace Owin.Security.OpenIdConnect.Server {
    internal partial class OpenIdConnectServerHandler : AuthenticationHandler<OpenIdConnectServerOptions> {
        private async Task<bool> InvokeLogoutEndpointAsync() {
            OpenIdConnectMessage request;

            // Note: logout requests must be made via GET but POST requests
            // are also accepted to allow flowing large logout payloads.
            // See https://openid.net/specs/openid-connect-session-1_0.html#RPLogout
            if (string.Equals(Request.Method, "GET", StringComparison.OrdinalIgnoreCase)) {
                request = new OpenIdConnectMessage(Request.Query) {
                    RequestType = OpenIdConnectRequestType.LogoutRequest
                };
            }

            else if (string.Equals(Request.Method, "POST", StringComparison.OrdinalIgnoreCase)) {
                // See http://openid.net/specs/openid-connect-core-1_0.html#FormSerialization
                if (string.IsNullOrEmpty(Request.ContentType)) {
                    Options.Logger.LogError("The logout request was rejected because " +
                                            "the mandatory 'Content-Type' header was missing.");

                    return await SendLogoutResponseAsync(null, new OpenIdConnectMessage {
                        Error = OpenIdConnectConstants.Errors.InvalidRequest,
                        ErrorDescription = "A malformed logout request has been received: " +
                            "the mandatory 'Content-Type' header was missing from the POST request."
                    });
                }

                // May have media/type; charset=utf-8, allow partial match.
                if (!Request.ContentType.StartsWith("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase)) {
                    Options.Logger.LogError("The logout request was rejected because an invalid 'Content-Type' " +
                                            "header was received: {ContentType}.", Request.ContentType);

                    return await SendLogoutResponseAsync(null, new OpenIdConnectMessage {
                        Error = OpenIdConnectConstants.Errors.InvalidRequest,
                        ErrorDescription = "A malformed logout request has been received: " +
                            "the 'Content-Type' header contained an unexcepted value. " +
                            "Make sure to use 'application/x-www-form-urlencoded'."
                    });
                }

                request = new OpenIdConnectMessage(await Request.ReadFormAsync()) {
                    RequestType = OpenIdConnectRequestType.LogoutRequest
                };
            }

            else {
                Options.Logger.LogError("The logout request was rejected because an invalid " +
                                        "HTTP method was received: {Method}.", Request.Method);

                return await SendLogoutResponseAsync(null, new OpenIdConnectMessage {
                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = "A malformed logout request has been received: " +
                                       "make sure to use either GET or POST."
                });
            }

            // Store the logout request in the OWIN context.
            Context.SetOpenIdConnectRequest(request);

            var context = new ValidateLogoutRequestContext(Context, Options, request);
            await Options.Provider.ValidateLogoutRequest(context);

            if (context.IsRejected) {
                Options.Logger.LogError("The logout request was rejected with the following error: {Error} ; {Description}",
                                        /* Error: */ context.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
                                        /* Description: */ context.ErrorDescription);

                return await SendLogoutResponseAsync(request, new OpenIdConnectMessage {
                    Error = context.Error,
                    ErrorDescription = context.ErrorDescription,
                    ErrorUri = context.ErrorUri
                });
            }

            var notification = new HandleLogoutRequestContext(Context, Options, request);
            await Options.Provider.HandleLogoutRequest(notification);

            if (notification.HandledResponse) {
                return true;
            }

            else if (notification.Skipped) {
                return false;
            }

            return false;
        }

        private async Task<bool> HandleLogoutResponseAsync() {
            // request may be null when no logout request has been received
            // or has been already handled by InvokeLogoutEndpointAsync.
            var request = Context.GetOpenIdConnectRequest();
            if (request == null) {
                return false;
            }

            // Stop processing the request if there's no signout context that matches
            // the authentication type associated with this middleware instance
            // or if the response status code doesn't indicate a successful response.
            var context = Helper.LookupSignOut(Options.AuthenticationType, Options.AuthenticationMode);
            if (context == null || Response.StatusCode != 200) {
                return false;
            }

            var response = new OpenIdConnectMessage {
                PostLogoutRedirectUri = request.PostLogoutRedirectUri,
                State = request.State
            };

            return await SendLogoutResponseAsync(request, response);
        }

        private async Task<bool> SendLogoutResponseAsync(OpenIdConnectMessage request, OpenIdConnectMessage response) {
            if (request == null) {
                request = new OpenIdConnectMessage();
            }

            var notification = new ApplyLogoutResponseContext(Context, Options, request, response);
            await Options.Provider.ApplyLogoutResponse(notification);

            if (notification.HandledResponse) {
                return true;
            }

            else if (notification.Skipped) {
                return false;
            }

            if (!string.IsNullOrEmpty(response.Error)) {
                // When returning an error, remove the logout request from the OWIN context
                // to inform TeardownCoreAsync that there's nothing more to handle.
                Context.SetOpenIdConnectRequest(request: null);

                // Apply a 400 status code by default.
                Response.StatusCode = 400;

                if (Options.ApplicationCanDisplayErrors) {
                    Context.SetOpenIdConnectResponse(response);

                    // Return false to allow the rest of
                    // the pipeline to handle the request.
                    return false;
                }

                return await SendNativePageAsync(response);
            }

            // Don't redirect the user agent if no explicit post_logout_redirect_uri was
            // provided or if the URI was not fully validated by the application code.
            if (string.IsNullOrEmpty(response.PostLogoutRedirectUri)) {
                return true;
            }

            var location = response.PostLogoutRedirectUri;

            foreach (var parameter in response.Parameters) {
                // Don't include post_logout_redirect_uri in the query string.
                if (string.Equals(parameter.Key, OpenIdConnectParameterNames.PostLogoutRedirectUri, StringComparison.Ordinal)) {
                    continue;
                }

                location = WebUtilities.AddQueryString(location, parameter.Key, parameter.Value);
            }

            Response.Redirect(location);

            return true;
        }
    }
}
