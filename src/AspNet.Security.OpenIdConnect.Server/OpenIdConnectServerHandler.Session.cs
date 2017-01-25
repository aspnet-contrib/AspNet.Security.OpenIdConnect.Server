/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Primitives;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json.Linq;

namespace AspNet.Security.OpenIdConnect.Server {
    internal partial class OpenIdConnectServerHandler : AuthenticationHandler<OpenIdConnectServerOptions> {
        private async Task<bool> InvokeLogoutEndpointAsync() {
            OpenIdConnectRequest request;

            // Note: logout requests must be made via GET but POST requests
            // are also accepted to allow flowing large logout payloads.
            // See https://openid.net/specs/openid-connect-session-1_0.html#RPLogout
            if (string.Equals(Request.Method, "GET", StringComparison.OrdinalIgnoreCase)) {
                request = new OpenIdConnectRequest(Request.Query);
            }

            else if (string.Equals(Request.Method, "POST", StringComparison.OrdinalIgnoreCase)) {
                // See http://openid.net/specs/openid-connect-core-1_0.html#FormSerialization
                if (string.IsNullOrEmpty(Request.ContentType)) {
                    Logger.LogError("The logout request was rejected because " +
                                    "the mandatory 'Content-Type' header was missing.");

                    return await SendLogoutResponseAsync(new OpenIdConnectResponse {
                        Error = OpenIdConnectConstants.Errors.InvalidRequest,
                        ErrorDescription = "A malformed logout request has been received: " +
                            "the mandatory 'Content-Type' header was missing from the POST request."
                    });
                }

                // May have media/type; charset=utf-8, allow partial match.
                if (!Request.ContentType.StartsWith("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase)) {
                    Logger.LogError("The logout request was rejected because an invalid 'Content-Type' " +
                                    "header was received: {ContentType}.", Request.ContentType);

                    return await SendLogoutResponseAsync(new OpenIdConnectResponse {
                        Error = OpenIdConnectConstants.Errors.InvalidRequest,
                        ErrorDescription = "A malformed logout request has been received: " +
                            "the 'Content-Type' header contained an unexcepted value. " +
                            "Make sure to use 'application/x-www-form-urlencoded'."
                    });
                }

                request = new OpenIdConnectRequest(await Request.ReadFormAsync(Context.RequestAborted));
            }

            else {
                Logger.LogError("The logout request was rejected because an invalid " +
                                "HTTP method was received: {Method}.", Request.Method);

                return await SendLogoutResponseAsync(new OpenIdConnectResponse {
                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = "A malformed logout request has been received: " +
                                       "make sure to use either GET or POST."
                });
            }

            // Note: set the message type before invoking the ExtractLogoutRequest event.
            request.SetProperty(OpenIdConnectConstants.Properties.MessageType,
                                OpenIdConnectConstants.MessageTypes.LogoutRequest);

            // Store the logout request in the ASP.NET context.
            Context.SetOpenIdConnectRequest(request);

            var @event = new ExtractLogoutRequestContext(Context, Options, request);
            await Options.Provider.ExtractLogoutRequest(@event);

            if (@event.HandledResponse) {
                return true;
            }

            else if (@event.Skipped) {
                return false;
            }

            else if (@event.IsRejected) {
                Logger.LogError("The logout request was rejected with the following error: {Error} ; {Description}",
                                /* Error: */ @event.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
                                /* Description: */ @event.ErrorDescription);

                return await SendLogoutResponseAsync(new OpenIdConnectResponse {
                    Error = @event.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = @event.ErrorDescription,
                    ErrorUri = @event.ErrorUri
                });
            }

            var context = new ValidateLogoutRequestContext(Context, Options, request);
            await Options.Provider.ValidateLogoutRequest(context);

            if (context.HandledResponse) {
                return true;
            }

            else if (context.Skipped) {
                return false;
            }

            else if (context.IsRejected) {
                Logger.LogError("The logout request was rejected with the following error: {Error} ; {Description}",
                                /* Error: */ context.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
                                /* Description: */ context.ErrorDescription);

                return await SendLogoutResponseAsync(new OpenIdConnectResponse {
                    Error = context.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
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

            else if (notification.IsRejected) {
                Logger.LogError("The logout request was rejected with the following error: {Error} ; {Description}",
                                /* Error: */ notification.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
                                /* Description: */ notification.ErrorDescription);

                return await SendLogoutResponseAsync(new OpenIdConnectResponse {
                    Error = notification.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = notification.ErrorDescription,
                    ErrorUri = notification.ErrorUri
                });
            }

            return false;
        }

        private async Task<bool> SendLogoutResponseAsync(OpenIdConnectResponse response) {
            var request = Context.GetOpenIdConnectRequest();
            Context.SetOpenIdConnectResponse(response);

            var notification = new ApplyLogoutResponseContext(Context, Options, request, response);
            await Options.Provider.ApplyLogoutResponse(notification);

            if (notification.HandledResponse) {
                return true;
            }

            else if (notification.Skipped) {
                return false;
            }

            if (!string.IsNullOrEmpty(response.Error)) {
                // Apply a 400 status code by default.
                Response.StatusCode = 400;

                if (Options.ApplicationCanDisplayErrors) {
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

            // Create a new parameters dictionary holding the name/value pairs.
            var parameters = new Dictionary<string, string>();

            foreach (var parameter in response.GetParameters()) {
                // Don't include post_logout_redirect_uri in the parameters dictionary.
                if (string.Equals(parameter.Key, OpenIdConnectConstants.Parameters.PostLogoutRedirectUri, StringComparison.Ordinal)) {
                    continue;
                }

                // Ignore null or empty parameters, including JSON
                // objects that can't be represented as strings.
                var value = (string) parameter.Value;
                if (string.IsNullOrEmpty(value)) {
                    continue;
                }

                parameters.Add(parameter.Key, value);
            }

            var location = QueryHelpers.AddQueryString(response.PostLogoutRedirectUri, parameters);

            Response.Redirect(location);
            return true;
        }
    }
}
