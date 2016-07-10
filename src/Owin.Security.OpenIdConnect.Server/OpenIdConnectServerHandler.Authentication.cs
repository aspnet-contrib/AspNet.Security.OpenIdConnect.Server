/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.Globalization;
using System.IO;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Protocols;
using Microsoft.Owin.Infrastructure;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using Owin.Security.OpenIdConnect.Extensions;

namespace Owin.Security.OpenIdConnect.Server {
    internal partial class OpenIdConnectServerHandler : AuthenticationHandler<OpenIdConnectServerOptions> {
        private async Task<bool> InvokeAuthorizationEndpointAsync() {
            OpenIdConnectMessage request;

            if (string.Equals(Request.Method, "GET", StringComparison.OrdinalIgnoreCase)) {
                // Create a new authorization request using the
                // parameters retrieved from the query string.
                request = new OpenIdConnectMessage(Request.Query) {
                    RequestType = OpenIdConnectRequestType.AuthenticationRequest
                };
            }

            else if (string.Equals(Request.Method, "POST", StringComparison.OrdinalIgnoreCase)) {
                // See http://openid.net/specs/openid-connect-core-1_0.html#FormSerialization
                if (string.IsNullOrEmpty(Request.ContentType)) {
                    Options.Logger.LogError("The authorization request was rejected because " +
                                            "the mandatory 'Content-Type' header was missing.");

                    return await SendAuthorizationResponseAsync(null, new OpenIdConnectMessage {
                        Error = OpenIdConnectConstants.Errors.InvalidRequest,
                        ErrorDescription = "A malformed authorization request has been received: " +
                            "the mandatory 'Content-Type' header was missing from the POST request."
                    });
                }

                // May have media/type; charset=utf-8, allow partial match.
                if (!Request.ContentType.StartsWith("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase)) {
                    Options.Logger.LogError("The authorization request was rejected because an invalid 'Content-Type' " +
                                            "header was received: {ContentType}.", Request.ContentType);

                    return await SendAuthorizationResponseAsync(null, new OpenIdConnectMessage {
                        Error = OpenIdConnectConstants.Errors.InvalidRequest,
                        ErrorDescription = "A malformed authorization request has been received: " +
                            "the 'Content-Type' header contained an unexcepted value. " +
                            "Make sure to use 'application/x-www-form-urlencoded'."
                    });
                }

                // Create a new authorization request using the
                // parameters retrieved from the request form.
                request = new OpenIdConnectMessage(await Request.ReadFormAsync()) {
                    RequestType = OpenIdConnectRequestType.AuthenticationRequest
                };
            }

            else {
                Options.Logger.LogError("The authorization request was rejected because an invalid " +
                                        "HTTP method was received: {Method}.", Request.Method);

                return await SendAuthorizationResponseAsync(null, new OpenIdConnectMessage {
                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = "A malformed authorization request has been received: " +
                                       "make sure to use either GET or POST."
                });
            }

            var @event = new ExtractAuthorizationRequestContext(Context, Options, request);
            await Options.Provider.ExtractAuthorizationRequest(@event);

            // Allow the application code to replace the authorization request.
            request = @event.Request;

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

                return await SendAuthorizationResponseAsync(null, new OpenIdConnectMessage {
                    Error = @event.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = @event.ErrorDescription,
                    ErrorUri = @event.ErrorUri
                });
            }

            // Store the authorization request in the OWIN context.
            Context.SetOpenIdConnectRequest(request);

            // client_id is mandatory parameter and MUST cause an error when missing.
            // See http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
            if (string.IsNullOrEmpty(request.ClientId)) {
                Options.Logger.LogError("The authorization request was rejected because " +
                                        "the mandatory 'client_id' parameter was missing.");

                return await SendAuthorizationResponseAsync(request, new OpenIdConnectMessage {
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

                return await SendAuthorizationResponseAsync(request, new OpenIdConnectMessage {
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

                    return await SendAuthorizationResponseAsync(request, new OpenIdConnectMessage {
                        Error = OpenIdConnectConstants.Errors.InvalidRequest,
                        ErrorDescription = "redirect_uri must be absolute"
                    });
                }

                // Note: when specified, redirect_uri MUST NOT include a fragment component.
                // See http://tools.ietf.org/html/rfc6749#section-3.1.2
                // and http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
                else if (!string.IsNullOrEmpty(uri.Fragment)) {
                    Options.Logger.LogError("The authorization request was rejected because the 'redirect_uri' " +
                                            "contained a URL fragment: {RedirectUri}.", request.RedirectUri);

                    return await SendAuthorizationResponseAsync(request, new OpenIdConnectMessage {
                        Error = OpenIdConnectConstants.Errors.InvalidRequest,
                        ErrorDescription = "redirect_uri must not include a fragment"
                    });
                }
            }

            // Reject requests missing the mandatory response_type parameter.
            if (string.IsNullOrEmpty(request.ResponseType)) {
                Options.Logger.LogError("The authorization request was rejected because " +
                                        "the mandatory 'response_type' parameter was missing.");

                return await SendAuthorizationResponseAsync(request, new OpenIdConnectMessage {
                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = "response_type parameter missing"
                });
            }

            // response_mode=query (explicit or not) and a response_type containing id_token
            // or token are not considered as a safe combination and MUST be rejected.
            // See http://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#Security
            else if (request.IsQueryResponseMode() && (request.HasResponseType(OpenIdConnectConstants.ResponseTypes.IdToken) ||
                                                       request.HasResponseType(OpenIdConnectConstants.ResponseTypes.Token))) {
                Options.Logger.LogError("The authorization request was rejected because the 'response_type'/'response_mode' combination " +
                                        "was unsafe: {ResponseType} ; {ResponseMode}.", request.ResponseType, request.ResponseMode);

                return await SendAuthorizationResponseAsync(request, new OpenIdConnectMessage {
                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = "response_type/response_mode combination unsupported"
                });
            }

            // Reject OpenID Connect implicit/hybrid requests missing the mandatory nonce parameter.
            // See http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest,
            // http://openid.net/specs/openid-connect-implicit-1_0.html#RequestParameters
            // and http://openid.net/specs/openid-connect-core-1_0.html#HybridIDToken.
            else if (string.IsNullOrEmpty(request.Nonce) && request.HasScope(OpenIdConnectConstants.Scopes.OpenId) &&
                                                           (request.IsImplicitFlow() || request.IsHybridFlow())) {
                Options.Logger.LogError("The authorization request was rejected because " +
                                        "the mandatory 'nonce' parameter was missing.");

                return await SendAuthorizationResponseAsync(request, new OpenIdConnectMessage {
                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = "nonce parameter missing"
                });
            }

            // Reject requests containing the id_token response_type if no openid scope has been received.
            else if (request.HasResponseType(OpenIdConnectConstants.ResponseTypes.IdToken) &&
                    !request.HasScope(OpenIdConnectConstants.Scopes.OpenId)) {
                Options.Logger.LogError("The authorization request was rejected because the 'openid' scope was missing.");

                return await SendAuthorizationResponseAsync(request, new OpenIdConnectMessage {
                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = "openid scope missing"
                });
            }

            // Reject requests containing the code response_type if the token endpoint has been disabled.
            else if (request.HasResponseType(OpenIdConnectConstants.ResponseTypes.Code) && !Options.TokenEndpointPath.HasValue) {
                Options.Logger.LogError("The authorization request was rejected because the authorization code flow was disabled.");

                return await SendAuthorizationResponseAsync(request, new OpenIdConnectMessage {
                    Error = OpenIdConnectConstants.Errors.UnsupportedResponseType,
                    ErrorDescription = "response_type=code is not supported by this server"
                });
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

                return await SendAuthorizationResponseAsync(request, new OpenIdConnectMessage {
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

                return await SendAuthorizationResponseAsync(request, new OpenIdConnectMessage {
                    Error = notification.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = notification.ErrorDescription,
                    ErrorUri = notification.ErrorUri
                });
            }

            return false;
        }

        private async Task<bool> HandleAuthorizationResponseAsync() {
            // request may be null when no authorization request has been received
            // or has been already handled by InvokeAuthorizationEndpointAsync.
            var request = Context.GetOpenIdConnectRequest();
            if (request == null) {
                return false;
            }

            // Stop processing the request if there's no response grant that matches
            // the authentication type associated with this middleware instance
            // or if the response status code doesn't indicate a successful response.
            var context = Helper.LookupSignIn(Options.AuthenticationType);
            if (context == null || Response.StatusCode != 200) {
                return false;
            }

            if (!context.Principal.HasClaim(claim => claim.Type == ClaimTypes.NameIdentifier)) {
                throw new InvalidOperationException("The authentication ticket was rejected because it didn't " +
                                                    "contain the mandatory ClaimTypes.NameIdentifier claim.");
            }

            var response = new OpenIdConnectMessage {
                RedirectUri = request.RedirectUri,
                State = request.State
            };

            if (!string.IsNullOrEmpty(request.Nonce)) {
                // Keep the original nonce parameter for later comparison.
                context.Properties.Dictionary[OpenIdConnectConstants.Properties.Nonce] = request.Nonce;
            }

            if (!string.IsNullOrEmpty(request.RedirectUri)) {
                // Keep original the original redirect_uri for later comparison.
                context.Properties.Dictionary[OpenIdConnectConstants.Properties.RedirectUri] = request.RedirectUri;
            }

            // Always include the "openid" scope when the developer doesn't explicitly call SetScopes.
            // Note: the application is allowed to specify a different "scopes"
            // parameter when calling AuthenticationManager.SignInAsync: in this case,
            // don't replace the "scopes" property stored in the authentication ticket.
            if (!context.Properties.Dictionary.ContainsKey(OpenIdConnectConstants.Properties.Scopes) &&
                 request.HasScope(OpenIdConnectConstants.Scopes.OpenId)) {
                context.Properties.Dictionary[OpenIdConnectConstants.Properties.Scopes] = OpenIdConnectConstants.Scopes.OpenId;
            }

            string audiences;
            // When a "resources" property cannot be found in the authentication properties, infer it from the "audiences" property.
            if (!context.Properties.Dictionary.ContainsKey(OpenIdConnectConstants.Properties.Resources) &&
                 context.Properties.Dictionary.TryGetValue(OpenIdConnectConstants.Properties.Audiences, out audiences)) {
                context.Properties.Dictionary[OpenIdConnectConstants.Properties.Resources] = audiences;
            }

            // Determine whether an authorization code should be returned
            // and invoke SerializeAuthorizationCodeAsync if necessary.
            if (request.HasResponseType(OpenIdConnectConstants.ResponseTypes.Code)) {
                // Make sure to create a copy of the authentication properties
                // to avoid modifying the properties set on the original ticket.
                var properties = context.Properties.Copy();

                // properties.IssuedUtc and properties.ExpiresUtc are always
                // explicitly set to null to avoid aligning the expiration date
                // of the authorization code with the lifetime of the other tokens.
                properties.IssuedUtc = properties.ExpiresUtc = null;

                response.Code = await SerializeAuthorizationCodeAsync(context.Identity, properties, request, response);

                // Ensure that an authorization code is issued to avoid returning an invalid response.
                // See http://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#Combinations
                if (string.IsNullOrEmpty(response.Code)) {
                    throw new InvalidOperationException("An error occurred during the serialization of the " +
                                                        "authorization code and a null value was returned.");
                }
            }

            // Determine whether an access token should be returned
            // and invoke SerializeAccessTokenAsync if necessary.
            if (request.HasResponseType(OpenIdConnectConstants.ResponseTypes.Token)) {
                // Make sure to create a copy of the authentication properties
                // to avoid modifying the properties set on the original ticket.
                var properties = context.Properties.Copy();

                // Note: when the "resource" parameter added to the OpenID Connect response
                // is identical to the request parameter, returning it is not necessary.
                var resources = properties.GetProperty(OpenIdConnectConstants.Properties.Resources);
                if (!string.IsNullOrEmpty(request.Resource) && !string.IsNullOrEmpty(resources) &&
                    !string.Equals(request.Resource, resources, StringComparison.Ordinal)) {
                    response.Resource = resources;
                }

                // Note: when the "scope" parameter added to the OpenID Connect response
                // is identical to the request parameter, returning it is not necessary.
                var scopes = properties.GetProperty(OpenIdConnectConstants.Properties.Scopes);
                if (!string.IsNullOrEmpty(request.Scope) && !string.IsNullOrEmpty(scopes) &&
                    !string.Equals(request.Scope, scopes, StringComparison.Ordinal)) {
                    response.Scope = scopes;
                }

                response.TokenType = OpenIdConnectConstants.TokenTypes.Bearer;
                response.AccessToken = await SerializeAccessTokenAsync(context.Identity, properties, request, response);

                // Ensure that an access token is issued to avoid returning an invalid response.
                // See http://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#Combinations
                if (string.IsNullOrEmpty(response.AccessToken)) {
                    throw new InvalidOperationException("An error occurred during the serialization of the " +
                                                        "access token and a null value was returned.");
                }

                // properties.ExpiresUtc is automatically set by SerializeAccessTokenAsync but the end user
                // is free to set a null value directly in the SerializeAccessToken event.
                if (properties.ExpiresUtc.HasValue && properties.ExpiresUtc > Options.SystemClock.UtcNow) {
                    var lifetime = properties.ExpiresUtc.Value - Options.SystemClock.UtcNow;
                    var expiration = (long) (lifetime.TotalSeconds + .5);

                    response.ExpiresIn = expiration.ToString(CultureInfo.InvariantCulture);
                }
            }

            // Determine whether an identity token should be returned
            // and invoke SerializeIdentityTokenAsync if necessary.
            // Note: the identity token MUST be created after the authorization code
            // and the access token to create appropriate at_hash and c_hash claims.
            if (request.HasResponseType(OpenIdConnectConstants.ResponseTypes.IdToken)) {
                // Make sure to create a copy of the authentication properties
                // to avoid modifying the properties set on the original ticket.
                var properties = context.Properties.Copy();

                response.IdToken = await SerializeIdentityTokenAsync(context.Identity, properties, request, response);

                // Ensure that an identity token is issued to avoid returning an invalid response.
                // See http://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#Combinations
                if (string.IsNullOrEmpty(response.IdToken)) {
                    throw new InvalidOperationException("An error occurred during the serialization of the " +
                                                        "identity token and a null value was returned.");
                }
            }

            var ticket = new AuthenticationTicket(context.Identity, context.Properties);

            return await SendAuthorizationResponseAsync(request, response, ticket);
        }

        private async Task<bool> HandleForbiddenResponseAsync() {
            // Stop processing the request if no OpenID Connect
            // message has been found in the current context.
            var request = Context.GetOpenIdConnectRequest();
            if (request == null) {
                return false;
            }

            // Stop processing the request if there's no challenge that matches
            // the authentication type associated with this middleware instance
            // or if the response status code doesn't indicate a challenge operation.
            var context = Helper.LookupChallenge(Options.AuthenticationType, Options.AuthenticationMode);
            if (context == null || Response.StatusCode != 403) {
                return false;
            }

            var response = new OpenIdConnectMessage {
                Error = OpenIdConnectConstants.Errors.AccessDenied,
                ErrorDescription = "The authorization grant has been denied by the resource owner",
                RedirectUri = request.RedirectUri,
                State = request.State
            };

            // Create a new ticket containing an empty identity and
            // the authentication properties extracted from the challenge.
            var ticket = new AuthenticationTicket(new ClaimsIdentity(), context.Properties);

            return await SendAuthorizationResponseAsync(request, response, ticket);
        }

        private async Task<bool> SendAuthorizationResponseAsync(
            OpenIdConnectMessage request, OpenIdConnectMessage response, AuthenticationTicket ticket = null) {
            if (request == null) {
                request = new OpenIdConnectMessage();
            }

            var notification = new ApplyAuthorizationResponseContext(Context, Options, ticket, request, response);
            await Options.Provider.ApplyAuthorizationResponse(notification);

            if (notification.HandledResponse) {
                return true;
            }

            else if (notification.Skipped) {
                return false;
            }

            if (!string.IsNullOrEmpty(response.Error)) {
                // When returning an error, remove the authorization request from the OWIN context
                // to inform TeardownCoreAsync that there's nothing more to handle.
                Context.SetOpenIdConnectRequest(request: null);

                // Directly display an error page if redirect_uri cannot be used to
                // redirect the user agent back to the client application.
                if (string.IsNullOrEmpty(response.RedirectUri)) {
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
            }

            // Note: at this stage, the redirect_uri parameter MUST be trusted.
            if (request.IsFormPostResponseMode()) {
                using (var buffer = new MemoryStream())
                using (var writer = new StreamWriter(buffer)) {
                    writer.WriteLine("<!doctype html>");
                    writer.WriteLine("<html>");
                    writer.WriteLine("<body>");

                    // While the redirect_uri parameter should be guarded against unknown values
                    // by IOpenIdConnectServerProvider.ValidateAuthorizationRequest,
                    // it's still safer to encode it to avoid cross-site scripting attacks
                    // if the authorization server has a relaxed policy concerning redirect URIs.
                    writer.WriteLine($"<form name='form' method='post' action='{Options.HtmlEncoder.Encode(response.RedirectUri)}'>");

                    foreach (var parameter in response.Parameters) {
                        // Don't include redirect_uri in the form.
                        if (string.Equals(parameter.Key, OpenIdConnectParameterNames.RedirectUri, StringComparison.Ordinal)) {
                            continue;
                        }

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

                foreach (var parameter in response.Parameters) {
                    // Don't include redirect_uri in the fragment.
                    if (string.Equals(parameter.Key, OpenIdConnectParameterNames.RedirectUri, StringComparison.Ordinal)) {
                        continue;
                    }

                    appender.Append(parameter.Key, parameter.Value);
                }

                Response.Redirect(appender.ToString());
                return true;
            }

            else if (request.IsQueryResponseMode()) {
                var location = response.RedirectUri;

                foreach (var parameter in response.Parameters) {
                    // Don't include redirect_uri in the query string.
                    if (string.Equals(parameter.Key, OpenIdConnectParameterNames.RedirectUri, StringComparison.Ordinal)) {
                        continue;
                    }

                    location = WebUtilities.AddQueryString(location, parameter.Key, parameter.Value);
                }

                Response.Redirect(location);
                return true;
            }

            Options.Logger.LogError("The authorization request was rejected because the 'response_mode' " +
                                    "parameter was invalid: {ResponseMode}.", request.ResponseMode);

            return await SendNativePageAsync(new OpenIdConnectMessage {
                Error = OpenIdConnectConstants.Errors.InvalidRequest,
                ErrorDescription = "response_mode unsupported"
            });
        }
    }
}
