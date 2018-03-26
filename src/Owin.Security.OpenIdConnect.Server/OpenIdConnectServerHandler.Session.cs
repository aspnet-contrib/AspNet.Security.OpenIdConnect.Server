/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Primitives;
using Microsoft.Extensions.Logging;
using Microsoft.Owin.Infrastructure;

namespace Owin.Security.OpenIdConnect.Server
{
    public partial class OpenIdConnectServerHandler
    {
        private async Task<bool> InvokeLogoutEndpointAsync()
        {
            OpenIdConnectRequest request;

            // Note: logout requests must be made via GET but POST requests
            // are also accepted to allow flowing large logout payloads.
            // See https://openid.net/specs/openid-connect-session-1_0.html#RPLogout
            if (string.Equals(Request.Method, "GET", StringComparison.OrdinalIgnoreCase))
            {
                request = new OpenIdConnectRequest(Request.Query);
            }

            else if (string.Equals(Request.Method, "POST", StringComparison.OrdinalIgnoreCase))
            {
                // See http://openid.net/specs/openid-connect-core-1_0.html#FormSerialization
                if (string.IsNullOrEmpty(Request.ContentType))
                {
                    Logger.LogError("The logout request was rejected because " +
                                    "the mandatory 'Content-Type' header was missing.");

                    return await SendLogoutResponseAsync(new OpenIdConnectResponse
                    {
                        Error = OpenIdConnectConstants.Errors.InvalidRequest,
                        ErrorDescription = "The mandatory 'Content-Type' header must be specified."
                    });
                }

                // May have media/type; charset=utf-8, allow partial match.
                if (!Request.ContentType.StartsWith("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase))
                {
                    Logger.LogError("The logout request was rejected because an invalid 'Content-Type' " +
                                    "header was specified: {ContentType}.", Request.ContentType);

                    return await SendLogoutResponseAsync(new OpenIdConnectResponse
                    {
                        Error = OpenIdConnectConstants.Errors.InvalidRequest,
                        ErrorDescription = "The specified 'Content-Type' header is not valid."
                    });
                }

                request = new OpenIdConnectRequest(await Request.ReadFormAsync());
            }

            else
            {
                Logger.LogError("The logout request was rejected because an invalid " +
                                "HTTP method was specified: {Method}.", Request.Method);

                return await SendLogoutResponseAsync(new OpenIdConnectResponse
                {
                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = "The specified HTTP method is not valid."
                });
            }

            // Note: set the message type before invoking the ExtractLogoutRequest event.
            request.SetProperty(OpenIdConnectConstants.Properties.MessageType,
                                OpenIdConnectConstants.MessageTypes.LogoutRequest);

            // Store the logout request in the OWIN context.
            Context.SetOpenIdConnectRequest(request);

            var @event = new ExtractLogoutRequestContext(Context, Options, request);
            await Options.Provider.ExtractLogoutRequest(@event);

            if (@event.HandledResponse)
            {
                Logger.LogDebug("The logout request was handled in user code.");

                return true;
            }

            else if (@event.Skipped)
            {
                Logger.LogDebug("The default logout request handling was skipped from user code.");

                return false;
            }

            else if (@event.IsRejected)
            {
                Logger.LogError("The logout request was rejected with the following error: {Error} ; {Description}",
                                /* Error: */ @event.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
                                /* Description: */ @event.ErrorDescription);

                return await SendLogoutResponseAsync(new OpenIdConnectResponse
                {
                    Error = @event.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = @event.ErrorDescription,
                    ErrorUri = @event.ErrorUri
                });
            }

            Logger.LogInformation("The logout request was successfully extracted " +
                                  "from the HTTP request: {Request}.", request);

            var context = new ValidateLogoutRequestContext(Context, Options, request);
            await Options.Provider.ValidateLogoutRequest(context);

            if (context.HandledResponse)
            {
                Logger.LogDebug("The logout request was handled in user code.");

                return true;
            }

            else if (context.Skipped)
            {
                Logger.LogDebug("The default logout request handling was skipped from user code.");

                return false;
            }

            else if (context.IsRejected)
            {
                Logger.LogError("The logout request was rejected with the following error: {Error} ; {Description}",
                                /* Error: */ context.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
                                /* Description: */ context.ErrorDescription);

                return await SendLogoutResponseAsync(new OpenIdConnectResponse
                {
                    Error = context.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = context.ErrorDescription,
                    ErrorUri = context.ErrorUri
                });
            }

            // Store the validated post_logout_redirect_uri as a request property.
            request.SetProperty(OpenIdConnectConstants.Properties.PostLogoutRedirectUri, context.PostLogoutRedirectUri);

            Logger.LogInformation("The logout request was successfully validated.");

            var notification = new HandleLogoutRequestContext(Context, Options, request);
            await Options.Provider.HandleLogoutRequest(notification);

            if (notification.HandledResponse)
            {
                Logger.LogDebug("The logout request was handled in user code.");

                return true;
            }

            else if (notification.Skipped)
            {
                Logger.LogDebug("The default logout request handling was skipped from user code.");

                return false;
            }

            else if (notification.IsRejected)
            {
                Logger.LogError("The logout request was rejected with the following error: {Error} ; {Description}",
                                /* Error: */ notification.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
                                /* Description: */ notification.ErrorDescription);

                return await SendLogoutResponseAsync(new OpenIdConnectResponse
                {
                    Error = notification.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = notification.ErrorDescription,
                    ErrorUri = notification.ErrorUri
                });
            }

            return false;
        }

        private async Task<bool> SendLogoutResponseAsync(OpenIdConnectResponse response)
        {
            var request = Context.GetOpenIdConnectRequest();
            Context.SetOpenIdConnectResponse(response);

            response.SetProperty(OpenIdConnectConstants.Properties.MessageType,
                                 OpenIdConnectConstants.MessageTypes.LogoutResponse);

            // Note: as this stage, the request may be null (e.g if it couldn't be extracted from the HTTP request).
            var notification = new ApplyLogoutResponseContext(Context, Options, request, response)
            {
                PostLogoutRedirectUri = request?.GetProperty<string>(OpenIdConnectConstants.Properties.PostLogoutRedirectUri)
            };

            await Options.Provider.ApplyLogoutResponse(notification);

            if (notification.HandledResponse)
            {
                Logger.LogDebug("The logout request was handled in user code.");

                return true;
            }

            else if (notification.Skipped)
            {
                Logger.LogDebug("The default logout request handling was skipped from user code.");

                return false;
            }

            if (!string.IsNullOrEmpty(response.Error))
            {
                // Apply a 400 status code by default.
                Response.StatusCode = 400;

                if (Options.ApplicationCanDisplayErrors)
                {
                    // Return false to allow the rest of
                    // the pipeline to handle the request.
                    return false;
                }

                Logger.LogInformation("The logout response was successfully returned " +
                                      "as a plain-text document: {Response}.", response);

                return await SendNativePageAsync(response);
            }

            // Don't redirect the user agent if no explicit post_logout_redirect_uri was
            // provided or if the URI was not fully validated by the application code.
            if (string.IsNullOrEmpty(notification.PostLogoutRedirectUri))
            {
                Logger.LogInformation("The logout response was successfully returned: {Response}.", response);

                return true;
            }

            // At this stage, throw an exception if the request was not properly extracted,
            if (request == null)
            {
                throw new InvalidOperationException("The logout response cannot be returned.");
            }

            // Attach the request state to the end session response.
            if (string.IsNullOrEmpty(response.State))
            {
                response.State = request.State;
            }

            // Note: a dictionary is deliberately not used here to allow multiple parameters with the
            // same name to be specified. While initially not allowed by the core OAuth2 specification,
            // this is now accepted by derived drafts like the OAuth2 token exchange specification.
            // For consistency, multiple parameters with the same name are also supported by this endpoint.
            var parameters = new List<KeyValuePair<string, string>>();

            foreach (var parameter in response.GetParameters())
            {
                var values = (string[]) parameter.Value;
                if (values == null)
                {
                    continue;
                }

                foreach (var value in values)
                {
                    parameters.Add(new KeyValuePair<string, string>(parameter.Key, value));
                }
            }

            Logger.LogInformation("The logout response was successfully returned to '{PostLogoutRedirectUri}': {Response}.",
                                  notification.PostLogoutRedirectUri, response);

            var location = notification.PostLogoutRedirectUri;

            foreach (var parameter in parameters)
            {
                location = WebUtilities.AddQueryString(location, parameter.Key, parameter.Value);
            }

            Response.Redirect(location);
            return true;
        }
    }
}
