/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Primitives;
using Microsoft.Extensions.Logging;
using Microsoft.Owin.Infrastructure;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using Newtonsoft.Json.Linq;
using Owin.Security.OpenIdConnect.Extensions;

namespace Owin.Security.OpenIdConnect.Server {
    internal partial class OpenIdConnectServerHandler : AuthenticationHandler<OpenIdConnectServerOptions> {
        private async Task<bool> InvokeAuthorizationEndpointAsync() {
            OpenIdConnectRequest request;

            if (string.Equals(Request.Method, "GET", StringComparison.OrdinalIgnoreCase)) {
                request = new OpenIdConnectRequest(Request.Query);
            }

            else if (string.Equals(Request.Method, "POST", StringComparison.OrdinalIgnoreCase)) {
                // See http://openid.net/specs/openid-connect-core-1_0.html#FormSerialization
                if (string.IsNullOrEmpty(Request.ContentType)) {
                    Options.Logger.LogError("The authorization request was rejected because " +
                                            "the mandatory 'Content-Type' header was missing.");

                    return await SendAuthorizationResponseAsync(new OpenIdConnectResponse {
                        Error = OpenIdConnectConstants.Errors.InvalidRequest,
                        ErrorDescription = "A malformed authorization request has been received: " +
                            "the mandatory 'Content-Type' header was missing from the POST request."
                    });
                }

                // May have media/type; charset=utf-8, allow partial match.
                if (!Request.ContentType.StartsWith("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase)) {
                    Options.Logger.LogError("The authorization request was rejected because an invalid 'Content-Type' " +
                                            "header was received: {ContentType}.", Request.ContentType);

                    return await SendAuthorizationResponseAsync(new OpenIdConnectResponse {
                        Error = OpenIdConnectConstants.Errors.InvalidRequest,
                        ErrorDescription = "A malformed authorization request has been received: " +
                            "the 'Content-Type' header contained an unexcepted value. " +
                            "Make sure to use 'application/x-www-form-urlencoded'."
                    });
                }

                request = new OpenIdConnectRequest(await Request.ReadFormAsync());
            }

            else {
                Options.Logger.LogError("The authorization request was rejected because an invalid " +
                                        "HTTP method was received: {Method}.", Request.Method);

                return await SendAuthorizationResponseAsync(new OpenIdConnectResponse {
                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = "A malformed authorization request has been received: " +
                                       "make sure to use either GET or POST."
                });
            }

            // Note: set the message type before invoking the ExtractAuthorizationRequest event.
            request.SetProperty(OpenIdConnectConstants.Properties.MessageType,
                                OpenIdConnectConstants.MessageTypes.Authorization);

            // Store the authorization request in the OWIN context.
            Context.SetOpenIdConnectRequest(request);

            var @event = new ExtractAuthorizationRequestContext(Context, Options, request);
            await Options.Provider.ExtractAuthorizationRequest(@event);

            if (@event.HandledResponse) {
                return true;
            }

            else if (@event.Skipped) {
                return false;
            }

            else if (@event.IsRejected) {
                Options.Logger.LogError("The authorization request was rejected with the following error: {Error} ; {Description}",
                                        /* Error: */ @event.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
                                        /* Description: */ @event.ErrorDescription);

                return await SendAuthorizationResponseAsync(new OpenIdConnectResponse {
                    Error = @event.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = @event.ErrorDescription,
                    ErrorUri = @event.ErrorUri
                });
            }

            // client_id is mandatory parameter and MUST cause an error when missing.
            // See http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
            if (string.IsNullOrEmpty(request.ClientId)) {
                Options.Logger.LogError("The authorization request was rejected because " +
                                        "the mandatory 'client_id' parameter was missing.");

                return await SendAuthorizationResponseAsync(new OpenIdConnectResponse {
                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = "client_id was missing"
                });
            }

            // While redirect_uri was not mandatory in OAuth2, this parameter
            // is now declared as REQUIRED and MUST cause an error when missing.
            // See http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
            // To keep AspNet.Security.OpenIdConnect.Server compatible with pure OAuth2 clients,
            // an error is only returned if the request was made by an OpenID Connect client.
            if (string.IsNullOrEmpty(request.RedirectUri) && request.HasScope(OpenIdConnectConstants.Scopes.OpenId)) {
                Options.Logger.LogError("The authorization request was rejected because " +
                                        "the mandatory 'redirect_uri' parameter was missing.");

                return await SendAuthorizationResponseAsync(new OpenIdConnectResponse {
                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = "redirect_uri must be included when making an OpenID Connect request"
                });
            }

            if (!string.IsNullOrEmpty(request.RedirectUri)) {
                // Note: when specified, redirect_uri MUST be an absolute URI.
                // See http://tools.ietf.org/html/rfc6749#section-3.1.2
                // and http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
                Uri uri;
                if (!Uri.TryCreate(request.RedirectUri, UriKind.Absolute, out uri)) {
                    Options.Logger.LogError("The authorization request was rejected because the 'redirect_uri' parameter " +
                                            "didn't correspond to a valid absolute URL: {RedirectUri}.", request.RedirectUri);

                    return await SendAuthorizationResponseAsync(new OpenIdConnectResponse {
                        Error = OpenIdConnectConstants.Errors.InvalidRequest,
                        ErrorDescription = "redirect_uri must be absolute"
                    });
                }

                // Note: when specified, redirect_uri MUST NOT include a fragment component.
                // See http://tools.ietf.org/html/rfc6749#section-3.1.2
                // and http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
                if (!string.IsNullOrEmpty(uri.Fragment)) {
                    Options.Logger.LogError("The authorization request was rejected because the 'redirect_uri' " +
                                            "contained a URL fragment: {RedirectUri}.", request.RedirectUri);

                    return await SendAuthorizationResponseAsync(new OpenIdConnectResponse {
                        Error = OpenIdConnectConstants.Errors.InvalidRequest,
                        ErrorDescription = "redirect_uri must not include a fragment"
                    });
                }
            }

            // Reject requests missing the mandatory response_type parameter.
            if (string.IsNullOrEmpty(request.ResponseType)) {
                Options.Logger.LogError("The authorization request was rejected because " +
                                        "the mandatory 'response_type' parameter was missing.");

                return await SendAuthorizationResponseAsync(new OpenIdConnectResponse {
                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = "response_type parameter missing"
                });
            }

            // response_mode=query (explicit or not) and a response_type containing id_token
            // or token are not considered as a safe combination and MUST be rejected.
            // See http://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#Security
            if (request.IsQueryResponseMode() && (request.HasResponseType(OpenIdConnectConstants.ResponseTypes.IdToken) ||
                                                  request.HasResponseType(OpenIdConnectConstants.ResponseTypes.Token))) {
                Options.Logger.LogError("The authorization request was rejected because the 'response_type'/'response_mode' combination " +
                                        "was unsafe: {ResponseType} ; {ResponseMode}.", request.ResponseType, request.ResponseMode);

                return await SendAuthorizationResponseAsync(new OpenIdConnectResponse {
                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = "response_type/response_mode combination unsupported"
                });
            }

            // Reject OpenID Connect implicit/hybrid requests missing the mandatory nonce parameter.
            // See http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest,
            // http://openid.net/specs/openid-connect-implicit-1_0.html#RequestParameters
            // and http://openid.net/specs/openid-connect-core-1_0.html#HybridIDToken.
            if (string.IsNullOrEmpty(request.Nonce) && request.HasScope(OpenIdConnectConstants.Scopes.OpenId) &&
                                                      (request.IsImplicitFlow() || request.IsHybridFlow())) {
                Options.Logger.LogError("The authorization request was rejected because " +
                                        "the mandatory 'nonce' parameter was missing.");

                return await SendAuthorizationResponseAsync(new OpenIdConnectResponse {
                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = "nonce parameter missing"
                });
            }

            // Reject requests containing the id_token response_type if no openid scope has been received.
            if (request.HasResponseType(OpenIdConnectConstants.ResponseTypes.IdToken) &&
               !request.HasScope(OpenIdConnectConstants.Scopes.OpenId)) {
                Options.Logger.LogError("The authorization request was rejected because the 'openid' scope was missing.");

                return await SendAuthorizationResponseAsync(new OpenIdConnectResponse {
                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = "openid scope missing"
                });
            }

            // Reject requests containing the id_token response_type if no asymmetric signing key have been registered.
            if (request.HasResponseType(OpenIdConnectConstants.ResponseTypes.IdToken) &&
               !Options.SigningCredentials.Any(credentials => credentials.SigningKey is AsymmetricSecurityKey)) {
                Options.Logger.LogError("The authorization request was rejected because the 'id_token' response type could not be honored. " +
                                        "To fix this error, consider registering a X.509 signing certificate or an ephemeral signing key.");

                return await SendAuthorizationResponseAsync(new OpenIdConnectResponse {
                    Error = OpenIdConnectConstants.Errors.UnsupportedResponseType,
                    ErrorDescription = "The specified response type is not supported by this server."
                });
            }

            // Reject requests containing the code response_type if the token endpoint has been disabled.
            if (request.HasResponseType(OpenIdConnectConstants.ResponseTypes.Code) && !Options.TokenEndpointPath.HasValue) {
                Options.Logger.LogError("The authorization request was rejected because the authorization code flow was disabled.");

                return await SendAuthorizationResponseAsync(new OpenIdConnectResponse {
                    Error = OpenIdConnectConstants.Errors.UnsupportedResponseType,
                    ErrorDescription = "response_type=code is not supported by this server"
                });
            }

            if (!string.IsNullOrEmpty(request.CodeChallenge) || !string.IsNullOrEmpty(request.CodeChallengeMethod)) {
                // When code_challenge or code_challenge_method is specified, ensure the response_type includes "code".
                if (!request.HasResponseType(OpenIdConnectConstants.ResponseTypes.Code)) {
                    Options.Logger.LogError("The authorization request was rejected because the response type " +
                                            "was not compatible with 'code_challenge'/'code_challenge_method'.");

                    return await SendAuthorizationResponseAsync(new OpenIdConnectResponse {
                        Error = OpenIdConnectConstants.Errors.InvalidRequest,
                        ErrorDescription = "The 'code_challenge' and 'code_challenge_method' parameters " +
                                           "can only be used with a response type containing 'code'."
                    });
                }

                if (!string.IsNullOrEmpty(request.CodeChallengeMethod)) {
                    // Ensure a code_challenge was specified if a code_challenge_method was used.
                    if (string.IsNullOrEmpty(request.CodeChallenge)) {
                        Options.Logger.LogError("The authorization request was rejected " +
                                                "because the code_challenge was missing.");

                        return await SendAuthorizationResponseAsync(new OpenIdConnectResponse {
                            Error = OpenIdConnectConstants.Errors.InvalidRequest,
                            ErrorDescription = "The 'code_challenge_method' parameter " +
                                               "cannot be used without 'code_challenge'."
                        });
                    }

                    // If a code_challenge_method was specified, ensure the algorithm is supported.
                    if (request.CodeChallengeMethod != OpenIdConnectConstants.CodeChallengeMethods.Plain &&
                        request.CodeChallengeMethod != OpenIdConnectConstants.CodeChallengeMethods.Sha256) {
                        Options.Logger.LogError("The authorization request was rejected because " +
                                                "the specified code challenge was not supported.");

                        return await SendAuthorizationResponseAsync(new OpenIdConnectResponse {
                            Error = OpenIdConnectConstants.Errors.InvalidRequest,
                            ErrorDescription = "The specified code_challenge_method is not supported."
                        });
                    }
                }
            }

            var context = new ValidateAuthorizationRequestContext(Context, Options, request);
            await Options.Provider.ValidateAuthorizationRequest(context);

            if (context.HandledResponse) {
                return true;
            }

            else if (context.Skipped) {
                return false;
            }

            else if (!context.IsValidated) {
                Options.Logger.LogError("The authorization request was rejected with the following error: {Error} ; {Description}",
                                        /* Error: */ context.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
                                        /* Description: */ context.ErrorDescription);

                return await SendAuthorizationResponseAsync(new OpenIdConnectResponse {
                    Error = context.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = context.ErrorDescription,
                    ErrorUri = context.ErrorUri
                });
            }

            var notification = new HandleAuthorizationRequestContext(Context, Options, request);
            await Options.Provider.HandleAuthorizationRequest(notification);

            if (notification.HandledResponse) {
                return true;
            }

            else if (notification.Skipped) {
                return false;
            }

            else if (notification.IsRejected) {
                Options.Logger.LogError("The authorization request was rejected with the following error: {Error} ; {Description}",
                                        /* Error: */ notification.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
                                        /* Description: */ notification.ErrorDescription);

                return await SendAuthorizationResponseAsync(new OpenIdConnectResponse {
                    Error = notification.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = notification.ErrorDescription,
                    ErrorUri = notification.ErrorUri
                });
            }

            // If an authentication ticket was provided, stop processing
            // the request and return an authorization response.
            var ticket = notification.Ticket;
            if (ticket == null) {
                return false;
            }

            return await HandleSignInAsync(ticket);
        }

        private async Task<bool> SendAuthorizationResponseAsync(OpenIdConnectResponse response, AuthenticationTicket ticket = null) {
            var request = Context.GetOpenIdConnectRequest();
            Context.SetOpenIdConnectResponse(response);

            var notification = new ApplyAuthorizationResponseContext(Context, Options, ticket, request, response);
            await Options.Provider.ApplyAuthorizationResponse(notification);

            if (notification.HandledResponse) {
                return true;
            }

            else if (notification.Skipped) {
                return false;
            }

            if (!string.IsNullOrEmpty(response.Error)) {
                // Directly display an error page if redirect_uri cannot be used to
                // redirect the user agent back to the client application.
                if (string.IsNullOrEmpty(response.RedirectUri)) {
                    // Apply a 400 status code by default.
                    Response.StatusCode = 400;

                    if (Options.ApplicationCanDisplayErrors) {
                        // Return false to allow the rest of
                        // the pipeline to handle the request.
                        return false;
                    }

                    return await SendNativePageAsync(response);
                }
            }

            // At this stage, throw an exception if the request was not properly extracted,
            // as the rest of this method depends on the request to determine the response mode.
            if (request == null) {
                throw new InvalidOperationException("The authorization response cannot be returned.");
            }

            // Create a new parameters dictionary holding the name/value pairs.
            var parameters = new Dictionary<string, string>();

            foreach (var parameter in response.GetParameters()) {
                // Don't include redirect_uri in the parameters dictionary.
                if (string.Equals(parameter.Key, OpenIdConnectConstants.Parameters.RedirectUri, StringComparison.Ordinal)) {
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

            // Note: at this stage, the redirect_uri parameter MUST be trusted.
            if (request.IsFormPostResponseMode()) {
                using (var buffer = new MemoryStream())
                using (var writer = new StreamWriter(buffer)) {
                    writer.WriteLine("<!doctype html>");
                    writer.WriteLine("<html>");
                    writer.WriteLine("<body>");

                    // While the redirect_uri parameter should be guarded against unknown values
                    // by OpenIdConnectServerProvider.ValidateAuthorizationRequest,
                    // it's still safer to encode it to avoid cross-site scripting attacks
                    // if the authorization server has a relaxed policy concerning redirect URIs.
                    writer.WriteLine($"<form name='form' method='post' action='{Options.HtmlEncoder.Encode(response.RedirectUri)}'>");

                    foreach (var parameter in parameters) {
                        var key = Options.HtmlEncoder.Encode(parameter.Key);
                        var value = Options.HtmlEncoder.Encode(parameter.Value);

                        writer.WriteLine($"<input type='hidden' name='{key}' value='{value}' />");
                    }

                    writer.WriteLine("<noscript>Click here to finish the authorization process: <input type='submit' /></noscript>");
                    writer.WriteLine("</form>");
                    writer.WriteLine("<script>document.form.submit();</script>");
                    writer.WriteLine("</body>");
                    writer.WriteLine("</html>");
                    writer.Flush();

                    Response.StatusCode = 200;
                    Response.ContentLength = buffer.Length;
                    Response.ContentType = "text/html;charset=UTF-8";

                    buffer.Seek(offset: 0, loc: SeekOrigin.Begin);
                    await buffer.CopyToAsync(Response.Body, 4096, Request.CallCancelled);

                    return true;
                }
            }

            else if (request.IsFragmentResponseMode()) {
                var location = response.RedirectUri;
                var appender = new Appender(location, '#');

                foreach (var parameter in parameters) {
                    appender.Append(parameter.Key, parameter.Value);
                }

                Response.Redirect(appender.ToString());
                return true;
            }

            else if (request.IsQueryResponseMode()) {
                var location = WebUtilities.AddQueryString(response.RedirectUri, parameters);

                Response.Redirect(location);
                return true;
            }

            Options.Logger.LogError("The authorization request was rejected because the 'response_mode' " +
                                    "parameter was invalid: {ResponseMode}.", request.ResponseMode);

            return await SendNativePageAsync(new OpenIdConnectResponse {
                Error = OpenIdConnectConstants.Errors.InvalidRequest,
                ErrorDescription = "response_mode unsupported"
            });
        }
    }
}
