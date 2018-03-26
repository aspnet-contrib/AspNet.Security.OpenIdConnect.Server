/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Primitives;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Owin.Infrastructure;
using Microsoft.Owin.Security;
using Owin.Security.OpenIdConnect.Extensions;

namespace Owin.Security.OpenIdConnect.Server
{
    public partial class OpenIdConnectServerHandler
    {
        private async Task<bool> InvokeAuthorizationEndpointAsync()
        {
            OpenIdConnectRequest request;

            if (string.Equals(Request.Method, "GET", StringComparison.OrdinalIgnoreCase))
            {
                request = new OpenIdConnectRequest(Request.Query);
            }

            else if (string.Equals(Request.Method, "POST", StringComparison.OrdinalIgnoreCase))
            {
                // See http://openid.net/specs/openid-connect-core-1_0.html#FormSerialization
                if (string.IsNullOrEmpty(Request.ContentType))
                {
                    Logger.LogError("The authorization request was rejected because " +
                                    "the mandatory 'Content-Type' header was missing.");

                    return await SendAuthorizationResponseAsync(new OpenIdConnectResponse
                    {
                        Error = OpenIdConnectConstants.Errors.InvalidRequest,
                        ErrorDescription = "The mandatory 'Content-Type' header must be specified."
                    });
                }

                // May have media/type; charset=utf-8, allow partial match.
                if (!Request.ContentType.StartsWith("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase))
                {
                    Logger.LogError("The authorization request was rejected because an invalid 'Content-Type' " +
                                    "header was specified: {ContentType}.", Request.ContentType);

                    return await SendAuthorizationResponseAsync(new OpenIdConnectResponse
                    {
                        Error = OpenIdConnectConstants.Errors.InvalidRequest,
                        ErrorDescription = "The specified 'Content-Type' header is not valid."
                    });
                }

                request = new OpenIdConnectRequest(await Request.ReadFormAsync());
            }

            else
            {
                Logger.LogError("The authorization request was rejected because an invalid " +
                                "HTTP method was specified: {Method}.", Request.Method);

                return await SendAuthorizationResponseAsync(new OpenIdConnectResponse
                {
                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = "The specified HTTP method is not valid."
                });
            }

            // Note: set the message type before invoking the ExtractAuthorizationRequest event.
            request.SetProperty(OpenIdConnectConstants.Properties.MessageType,
                                OpenIdConnectConstants.MessageTypes.AuthorizationRequest);

            // Store the authorization request in the OWIN context.
            Context.SetOpenIdConnectRequest(request);

            var @event = new ExtractAuthorizationRequestContext(Context, Options, request);
            await Options.Provider.ExtractAuthorizationRequest(@event);

            if (@event.HandledResponse)
            {
                Logger.LogDebug("The authorization request was handled in user code.");

                return true;
            }

            else if (@event.Skipped)
            {
                Logger.LogDebug("The default authorization request handling was skipped from user code.");

                return false;
            }

            else if (@event.IsRejected)
            {
                Logger.LogError("The authorization request was rejected with the following error: {Error} ; {Description}",
                                /* Error: */ @event.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
                                /* Description: */ @event.ErrorDescription);

                return await SendAuthorizationResponseAsync(new OpenIdConnectResponse
                {
                    Error = @event.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = @event.ErrorDescription,
                    ErrorUri = @event.ErrorUri
                });
            }

            // Store the original redirect_uri sent by the client application for later comparison.
            request.SetProperty(OpenIdConnectConstants.Properties.OriginalRedirectUri, request.RedirectUri);

            Logger.LogInformation("The authorization request was successfully extracted " +
                                  "from the HTTP request: {Request}.", request);

            // client_id is mandatory parameter and MUST cause an error when missing.
            // See http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
            if (string.IsNullOrEmpty(request.ClientId))
            {
                Logger.LogError("The authorization request was rejected because " +
                                "the mandatory 'client_id' parameter was missing.");

                return await SendAuthorizationResponseAsync(new OpenIdConnectResponse
                {
                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = "The mandatory 'client_id' parameter is missing."
                });
            }

            // While redirect_uri was not mandatory in OAuth2, this parameter
            // is now declared as REQUIRED and MUST cause an error when missing.
            // See http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
            // To keep AspNet.Security.OpenIdConnect.Server compatible with pure OAuth2 clients,
            // an error is only returned if the request was made by an OpenID Connect client.
            if (string.IsNullOrEmpty(request.RedirectUri) && request.HasScope(OpenIdConnectConstants.Scopes.OpenId))
            {
                Logger.LogError("The authorization request was rejected because " +
                                "the mandatory 'redirect_uri' parameter was missing.");

                return await SendAuthorizationResponseAsync(new OpenIdConnectResponse
                {
                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = "The mandatory 'redirect_uri' parameter is missing."
                });
            }

            if (!string.IsNullOrEmpty(request.RedirectUri))
            {
                // Note: when specified, redirect_uri MUST be an absolute URI.
                // See http://tools.ietf.org/html/rfc6749#section-3.1.2
                // and http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
                //
                // Note: on Linux/macOS, "/path" URLs are treated as valid absolute file URLs.
                // To ensure relative redirect_uris are correctly rejected on these platforms,
                // an additional check using IsWellFormedOriginalString() is made here.
                // See https://github.com/dotnet/corefx/issues/22098 for more information.
                if (!Uri.TryCreate(request.RedirectUri, UriKind.Absolute, out Uri uri) || !uri.IsWellFormedOriginalString())
                {
                    Logger.LogError("The authorization request was rejected because the 'redirect_uri' parameter " +
                                    "didn't correspond to a valid absolute URL: {RedirectUri}.", request.RedirectUri);

                    return await SendAuthorizationResponseAsync(new OpenIdConnectResponse
                    {
                        Error = OpenIdConnectConstants.Errors.InvalidRequest,
                        ErrorDescription = "The 'redirect_uri' parameter must be a valid absolute URL."
                    });
                }

                // Note: when specified, redirect_uri MUST NOT include a fragment component.
                // See http://tools.ietf.org/html/rfc6749#section-3.1.2
                // and http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
                if (!string.IsNullOrEmpty(uri.Fragment))
                {
                    Logger.LogError("The authorization request was rejected because the 'redirect_uri' " +
                                    "contained a URL fragment: {RedirectUri}.", request.RedirectUri);

                    return await SendAuthorizationResponseAsync(new OpenIdConnectResponse
                    {
                        Error = OpenIdConnectConstants.Errors.InvalidRequest,
                        ErrorDescription = "The 'redirect_uri' parameter must not include a fragment."
                    });
                }
            }

            // Reject requests missing the mandatory response_type parameter.
            if (string.IsNullOrEmpty(request.ResponseType))
            {
                Logger.LogError("The authorization request was rejected because " +
                                "the mandatory 'response_type' parameter was missing.");

                return await SendAuthorizationResponseAsync(new OpenIdConnectResponse
                {
                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = "The mandatory 'response_type' parameter is missing."
                });
            }

            // response_mode=query (explicit or not) and a response_type containing id_token
            // or token are not considered as a safe combination and MUST be rejected.
            // See http://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#Security
            if (request.IsQueryResponseMode() && (request.HasResponseType(OpenIdConnectConstants.ResponseTypes.IdToken) ||
                                                  request.HasResponseType(OpenIdConnectConstants.ResponseTypes.Token)))
            {
                Logger.LogError("The authorization request was rejected because the 'response_type'/'response_mode' combination " +
                                "was invalid: {ResponseType} ; {ResponseMode}.", request.ResponseType, request.ResponseMode);

                return await SendAuthorizationResponseAsync(new OpenIdConnectResponse
                {
                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = "The specified 'response_type'/'response_mode' combination is invalid."
                });
            }

            // Reject OpenID Connect implicit/hybrid requests missing the mandatory nonce parameter.
            // See http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest,
            // http://openid.net/specs/openid-connect-implicit-1_0.html#RequestParameters
            // and http://openid.net/specs/openid-connect-core-1_0.html#HybridIDToken.
            if (string.IsNullOrEmpty(request.Nonce) && request.HasScope(OpenIdConnectConstants.Scopes.OpenId) &&
                                                      (request.IsImplicitFlow() || request.IsHybridFlow()))
            {
                Logger.LogError("The authorization request was rejected because the mandatory 'nonce' parameter was missing.");

                return await SendAuthorizationResponseAsync(new OpenIdConnectResponse
                {
                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = "The mandatory 'nonce' parameter is missing."
                });
            }

            // Reject requests containing the id_token response_type if no openid scope has been received.
            if (request.HasResponseType(OpenIdConnectConstants.ResponseTypes.IdToken) &&
               !request.HasScope(OpenIdConnectConstants.Scopes.OpenId))
            {
                Logger.LogError("The authorization request was rejected because the 'openid' scope was missing.");

                return await SendAuthorizationResponseAsync(new OpenIdConnectResponse
                {
                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = "The mandatory 'openid' scope is missing."
                });
            }

            // Reject requests containing the id_token response_type if no asymmetric signing key has been registered.
            if (request.HasResponseType(OpenIdConnectConstants.ResponseTypes.IdToken) &&
               !Options.SigningCredentials.Any(credentials => credentials.Key is AsymmetricSecurityKey))
            {
                Logger.LogError("The authorization request was rejected because the 'id_token' response type could not be honored. " +
                                "To fix this error, consider registering a X.509 signing certificate or an ephemeral signing key.");

                return await SendAuthorizationResponseAsync(new OpenIdConnectResponse
                {
                    Error = OpenIdConnectConstants.Errors.UnsupportedResponseType,
                    ErrorDescription = "The specified 'response_type' is not supported by this server."
                });
            }

            // Reject requests containing the code response_type if the token endpoint has been disabled.
            if (request.HasResponseType(OpenIdConnectConstants.ResponseTypes.Code) && !Options.TokenEndpointPath.HasValue)
            {
                Logger.LogError("The authorization request was rejected because the authorization code flow was disabled.");

                return await SendAuthorizationResponseAsync(new OpenIdConnectResponse
                {
                    Error = OpenIdConnectConstants.Errors.UnsupportedResponseType,
                    ErrorDescription = "The specified 'response_type' is not supported by this server."
                });
            }

            // Reject requests specifying prompt=none with consent/login or select_account.
            if (request.HasPrompt(OpenIdConnectConstants.Prompts.None) && (request.HasPrompt(OpenIdConnectConstants.Prompts.Consent) ||
                                                                           request.HasPrompt(OpenIdConnectConstants.Prompts.Login) ||
                                                                           request.HasPrompt(OpenIdConnectConstants.Prompts.SelectAccount)))
            {
                Logger.LogError("The authorization request was rejected because an invalid prompt parameter was specified.");

                return await SendAuthorizationResponseAsync(new OpenIdConnectResponse
                {
                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = "The specified 'prompt' parameter is invalid."
                });
            }

            if (!string.IsNullOrEmpty(request.CodeChallenge) || !string.IsNullOrEmpty(request.CodeChallengeMethod))
            {
                // When code_challenge or code_challenge_method is specified, ensure the response_type includes "code".
                if (!request.HasResponseType(OpenIdConnectConstants.ResponseTypes.Code))
                {
                    Logger.LogError("The authorization request was rejected because the response type " +
                                    "was not compatible with 'code_challenge'/'code_challenge_method'.");

                    return await SendAuthorizationResponseAsync(new OpenIdConnectResponse
                    {
                        Error = OpenIdConnectConstants.Errors.InvalidRequest,
                        ErrorDescription = "The 'code_challenge' and 'code_challenge_method' parameters " +
                                           "can only be used with a response type containing 'code'."
                    });
                }

                if (!string.IsNullOrEmpty(request.CodeChallengeMethod))
                {
                    // Ensure a code_challenge was specified if a code_challenge_method was used.
                    if (string.IsNullOrEmpty(request.CodeChallenge))
                    {
                        Logger.LogError("The authorization request was rejected because the code_challenge was missing.");

                        return await SendAuthorizationResponseAsync(new OpenIdConnectResponse
                        {
                            Error = OpenIdConnectConstants.Errors.InvalidRequest,
                            ErrorDescription = "The 'code_challenge_method' parameter " +
                                               "cannot be used without 'code_challenge'."
                        });
                    }

                    // If a code_challenge_method was specified, ensure the algorithm is supported.
                    if (request.CodeChallengeMethod != OpenIdConnectConstants.CodeChallengeMethods.Plain &&
                        request.CodeChallengeMethod != OpenIdConnectConstants.CodeChallengeMethods.Sha256)
                    {
                        Logger.LogError("The authorization request was rejected because " +
                                        "the specified code challenge was not supported.");

                        return await SendAuthorizationResponseAsync(new OpenIdConnectResponse
                        {
                            Error = OpenIdConnectConstants.Errors.InvalidRequest,
                            ErrorDescription = "The specified code_challenge_method is not supported."
                        });
                    }
                }
            }

            var context = new ValidateAuthorizationRequestContext(Context, Options, request);
            await Options.Provider.ValidateAuthorizationRequest(context);

            if (context.HandledResponse)
            {
                Logger.LogDebug("The authorization request was handled in user code.");

                return true;
            }

            else if (context.Skipped)
            {
                Logger.LogDebug("The default authorization request handling was skipped from user code.");

                return false;
            }

            else if (context.IsRejected)
            {
                Logger.LogError("The authorization request was rejected with the following error: {Error} ; {Description}",
                                /* Error: */ context.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
                                /* Description: */ context.ErrorDescription);

                return await SendAuthorizationResponseAsync(new OpenIdConnectResponse
                {
                    Error = context.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = context.ErrorDescription,
                    ErrorUri = context.ErrorUri
                });
            }

            // Store the validated client_id/redirect_uri as request properties.
            request.SetProperty(OpenIdConnectConstants.Properties.ValidatedClientId, context.ClientId)
                   .SetProperty(OpenIdConnectConstants.Properties.ValidatedRedirectUri, context.RedirectUri);

            Logger.LogInformation("The authorization request was successfully validated.");

            var notification = new HandleAuthorizationRequestContext(Context, Options, request);
            await Options.Provider.HandleAuthorizationRequest(notification);

            if (notification.HandledResponse)
            {
                Logger.LogDebug("The authorization request was handled in user code.");

                return true;
            }

            else if (notification.Skipped)
            {
                Logger.LogDebug("The default authorization request handling was skipped from user code.");

                return false;
            }

            else if (notification.IsRejected)
            {
                Logger.LogError("The authorization request was rejected with the following error: {Error} ; {Description}",
                                /* Error: */ notification.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
                                /* Description: */ notification.ErrorDescription);

                return await SendAuthorizationResponseAsync(new OpenIdConnectResponse
                {
                    Error = notification.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = notification.ErrorDescription,
                    ErrorUri = notification.ErrorUri
                });
            }

            // If an authentication ticket was provided, stop processing
            // the request and return an authorization response.
            var ticket = notification.Ticket;
            if (ticket == null)
            {
                return false;
            }

            return await HandleSignInAsync(ticket);
        }

        private async Task<bool> SendAuthorizationResponseAsync(OpenIdConnectResponse response, AuthenticationTicket ticket = null)
        {
            var request = Context.GetOpenIdConnectRequest();
            Context.SetOpenIdConnectResponse(response);

            response.SetProperty(OpenIdConnectConstants.Properties.MessageType,
                                 OpenIdConnectConstants.MessageTypes.AuthorizationResponse);

            // Note: as this stage, the request may be null (e.g if it couldn't be extracted from the HTTP request).
            var notification = new ApplyAuthorizationResponseContext(Context, Options, ticket, request, response)
            {
                RedirectUri = request?.GetProperty<string>(OpenIdConnectConstants.Properties.ValidatedRedirectUri),
                ResponseMode = request?.ResponseMode
            };

            // If the response_mode parameter was not specified, try to infer it.
            if (string.IsNullOrEmpty(notification.ResponseMode) && !string.IsNullOrEmpty(notification.RedirectUri))
            {
                notification.ResponseMode =
                    request.IsFormPostResponseMode() ? OpenIdConnectConstants.ResponseModes.FormPost :
                    request.IsFragmentResponseMode() ? OpenIdConnectConstants.ResponseModes.Fragment :
                    request.IsQueryResponseMode()    ? OpenIdConnectConstants.ResponseModes.Query    : null;
            }

            await Options.Provider.ApplyAuthorizationResponse(notification);

            if (notification.HandledResponse)
            {
                Logger.LogDebug("The authorization request was handled in user code.");

                return true;
            }

            else if (notification.Skipped)
            {
                Logger.LogDebug("The default authorization request handling was skipped from user code.");

                return false;
            }

            // Directly display an error page if redirect_uri cannot be used to
            // redirect the user agent back to the client application.
            if (!string.IsNullOrEmpty(response.Error) && string.IsNullOrEmpty(notification.RedirectUri))
            {
                // Apply a 400 status code by default.
                Response.StatusCode = 400;

                if (Options.ApplicationCanDisplayErrors)
                {
                    // Return false to allow the rest of
                    // the pipeline to handle the request.
                    return false;
                }

                Logger.LogInformation("The authorization response was successfully returned " +
                                      "as a plain-text document: {Response}.", response);

                return await SendNativePageAsync(response);
            }

            // At this stage, throw an exception if the request was not properly extracted.
            if (request == null)
            {
                throw new InvalidOperationException("The authorization response cannot be returned.");
            }

            // Attach the request state to the authorization response.
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

            // Note: at this stage, the redirect_uri parameter MUST be trusted.
            switch (notification.ResponseMode)
            {
                case OpenIdConnectConstants.ResponseModes.FormPost:
                {
                    Logger.LogInformation("The authorization response was successfully returned to " +
                                          "'{RedirectUri}' using the form post response mode: {Response}.",
                                          notification.RedirectUri, response);

                    using (var buffer = new MemoryStream())
                    using (var writer = new StreamWriter(buffer))
                    {
                        writer.WriteLine("<!doctype html>");
                        writer.WriteLine("<html>");
                        writer.WriteLine("<body>");

                        // While the redirect_uri parameter should be guarded against unknown values
                        // by OpenIdConnectServerProvider.ValidateAuthorizationRequest,
                        // it's still safer to encode it to avoid cross-site scripting attacks
                        // if the authorization server has a relaxed policy concerning redirect URIs.
                        writer.WriteLine($@"<form name=""form"" method=""post"" action=""{Options.HtmlEncoder.Encode(notification.RedirectUri)}"">");

                        foreach (var parameter in parameters)
                        {
                            var key = Options.HtmlEncoder.Encode(parameter.Key);
                            var value = Options.HtmlEncoder.Encode(parameter.Value);

                            writer.WriteLine($@"<input type=""hidden"" name=""{key}"" value=""{value}"" />");
                        }

                        writer.WriteLine(@"<noscript>Click here to finish the authorization process: <input type=""submit"" /></noscript>");
                        writer.WriteLine("</form>");
                        writer.WriteLine("<script>document.form.submit();</script>");
                        writer.WriteLine("</body>");
                        writer.WriteLine("</html>");
                        writer.Flush();

                        Response.StatusCode = 200;
                        Response.ContentLength = buffer.Length;
                        Response.ContentType = "text/html;charset=UTF-8";

                        Response.Headers["Cache-Control"] = "no-cache";
                        Response.Headers["Pragma"] = "no-cache";
                        Response.Headers["Expires"] = "-1";

                        buffer.Seek(offset: 0, loc: SeekOrigin.Begin);
                        await buffer.CopyToAsync(Response.Body, 4096, Request.CallCancelled);

                        return true;
                    }
                }

                case OpenIdConnectConstants.ResponseModes.Fragment:
                {
                    Logger.LogInformation("The authorization response was successfully returned to " +
                                          "'{RedirectUri}' using the fragment response mode: {Response}.",
                                          notification.RedirectUri, response);

                    var location = notification.RedirectUri;
                    var appender = new OpenIdConnectServerHelpers.Appender(location, '#');

                    foreach (var parameter in parameters)
                    {
                        appender.Append(parameter.Key, parameter.Value);
                    }

                    Response.Redirect(appender.ToString());
                    return true;
                }

                case OpenIdConnectConstants.ResponseModes.Query:
                {
                    Logger.LogInformation("The authorization response was successfully returned to " +
                                          "'{RedirectUri}' using the query response mode: {Response}.",
                                          notification.RedirectUri, response);

                    var location = notification.RedirectUri;

                    foreach (var parameter in parameters)
                    {
                        location = WebUtilities.AddQueryString(location, parameter.Key, parameter.Value);
                    }

                    Response.Redirect(location);
                    return true;
                }

                default:
                {
                    Logger.LogError("The authorization request was rejected because the 'response_mode' " +
                                    "parameter was invalid: {ResponseMode}.", request.ResponseMode);

                    return await SendNativePageAsync(new OpenIdConnectResponse
                    {
                        Error = OpenIdConnectConstants.Errors.InvalidRequest,
                        ErrorDescription = "The specified 'response_mode' parameter is not supported."
                    });
                }
            }
        }
    }
}
