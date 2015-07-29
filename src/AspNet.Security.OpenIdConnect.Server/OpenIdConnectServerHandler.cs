/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IdentityModel.Tokens;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Extensions;
using Microsoft.AspNet.Authentication;
using Microsoft.AspNet.Http.Authentication;
using Microsoft.AspNet.Http.Features.Authentication;
using Microsoft.AspNet.WebUtilities;
using Microsoft.Framework.Caching.Distributed;
using Microsoft.Framework.Logging;
using Microsoft.IdentityModel.Protocols;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace AspNet.Security.OpenIdConnect.Server {
    internal class OpenIdConnectServerHandler : AuthenticationHandler<OpenIdConnectServerOptions> {
        protected override async Task<AuthenticationTicket> HandleAuthenticateAsync() {
            var notification = new MatchEndpointNotification(Context, Options);

            if (Options.AuthorizationEndpointPath.HasValue &&
                Options.AuthorizationEndpointPath == Request.Path) {
                notification.MatchesAuthorizationEndpoint();
            }

            else if (Options.LogoutEndpointPath.HasValue &&
                     Options.LogoutEndpointPath == Request.Path) {
                notification.MatchesLogoutEndpoint();
            }

            await Options.Provider.MatchEndpoint(notification);
            
            if (notification.IsAuthorizationEndpoint || notification.IsLogoutEndpoint) {
                // Invalid authorization or logout requests are ignored in AuthenticateAsync:
                // in this case, null is always returned to indicate authentication failed.
                var request = Context.GetOpenIdConnectRequest();
                if (request == null) {
                    return null;
                }

                if (string.IsNullOrEmpty(request.IdTokenHint)) {
                    return null;
                }

                var ticket = await ReceiveIdentityTokenAsync(request.IdTokenHint, request);
                if (ticket == null) {
                    Logger.LogVerbose("Invalid id_token_hint");

                    return null;
                }

                // Tickets are returned even if they
                // are considered invalid (e.g expired).
                return ticket;
            }

            return null;
        }

        public override async Task<bool> InvokeAsync() {
            var notification = new MatchEndpointNotification(Context, Options);

            if (Options.AuthorizationEndpointPath.HasValue &&
                Options.AuthorizationEndpointPath == Request.Path) {
                notification.MatchesAuthorizationEndpoint();
            }

            else if (Options.TokenEndpointPath.HasValue &&
                     Options.TokenEndpointPath == Request.Path) {
                notification.MatchesTokenEndpoint();
            }

            else if (Options.ValidationEndpointPath.HasValue &&
                     Options.ValidationEndpointPath == Request.Path) {
                notification.MatchesValidationEndpoint();
            }

            else if (Options.LogoutEndpointPath.HasValue &&
                     Options.LogoutEndpointPath == Request.Path) {
                notification.MatchesLogoutEndpoint();
            }

            else if (Options.ConfigurationEndpointPath.HasValue &&
                     Options.ConfigurationEndpointPath == Request.Path) {
                notification.MatchesConfigurationEndpoint();
            }

            else if (Options.CryptographyEndpointPath.HasValue &&
                     Options.CryptographyEndpointPath == Request.Path) {
                notification.MatchesCryptographyEndpoint();
            }

            await Options.Provider.MatchEndpoint(notification);

            if (notification.HandledResponse) {
                return true;
            }

            else if (notification.Skipped) {
                return false;
            }

            if (!Options.AllowInsecureHttp && !Request.IsHttps) {
                Logger.LogWarning("Authorization server ignoring http request because AllowInsecureHttp is false.");
                return false;
            }

            else if (notification.IsAuthorizationEndpoint) {
                return await InvokeAuthorizationEndpointAsync();
            }

            else if (notification.IsLogoutEndpoint) {
                return await InvokeLogoutEndpointAsync();
            }

            else if (notification.IsTokenEndpoint) {
                await InvokeTokenEndpointAsync();
                return true;
            }

            else if (notification.IsValidationEndpoint) {
                await InvokeValidationEndpointAsync();
                return true;
            }

            else if (notification.IsConfigurationEndpoint) {
                await InvokeConfigurationEndpointAsync();
                return true;
            }

            else if (notification.IsCryptographyEndpoint) {
                await InvokeCryptographyEndpointAsync();
                return true;
            }

            return false;
        }

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
                    Logger.LogInformation("A malformed request has been received by the authorization endpoint.");

                    return await SendErrorPageAsync(new OpenIdConnectMessage {
                        Error = OpenIdConnectConstants.Errors.InvalidRequest,
                        ErrorDescription = "A malformed authorization request has been received: " +
                            "the mandatory 'Content-Type' header was missing from the POST request."
                    });
                }

                // May have media/type; charset=utf-8, allow partial match.
                if (!Request.ContentType.StartsWith("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase)) {
                    Logger.LogInformation("A malformed request has been received by the authorization endpoint.");

                    return await SendErrorPageAsync(new OpenIdConnectMessage {
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
                Logger.LogInformation("A malformed request has been received by the authorization endpoint.");

                return await SendErrorPageAsync(new OpenIdConnectMessage {
                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = "A malformed authorization request has been received: " +
                        "make sure to use either GET or POST."
                });
            }

            // Re-assemble the authorization request using the distributed cache if
            // a 'unique_id' parameter has been extracted from the received message.
            var identifier = request.GetUniqueIdentifier();
            if (!string.IsNullOrEmpty(identifier)) {
                var buffer = await Options.Cache.GetAsync(identifier);
                if (buffer == null) {
                    Logger.LogInformation("A unique_id has been provided but no corresponding " +
                                          "OpenID Connect request has been found in the distributed cache.");

                    return await SendErrorPageAsync(new OpenIdConnectMessage {
                        Error = OpenIdConnectConstants.Errors.InvalidRequest,
                        ErrorDescription = "Invalid request: timeout expired."
                    });
                }

                using (var stream = new MemoryStream(buffer))
                using (var reader = new BinaryReader(stream)) {
                    // Make sure the stored authorization request
                    // has been serialized using the same method.
                    var version = reader.ReadInt32();
                    if (version != 1) {
                        await Options.Cache.RemoveAsync(identifier);

                        Logger.LogError("An invalid OpenID Connect request has been found in the distributed cache.");

                        return await SendErrorPageAsync(new OpenIdConnectMessage {
                            Error = OpenIdConnectConstants.Errors.InvalidRequest,
                            ErrorDescription = "Invalid request: timeout expired."
                        });
                    }
                    
                    for (int index = 0, length = reader.ReadInt32(); index < length; index++) {
                        var name = reader.ReadString();
                        var value = reader.ReadString();

                        // Skip restoring the parameter retrieved from the stored request
                        // if the OpenID Connect message extracted from the query string
                        // or the request form defined the same parameter.
                        if (!request.Parameters.ContainsKey(name)) {
                            request.SetParameter(name, value);
                        }
                    }
                }
            }

            // Insert the authorization request in the ASP.NET context.
            Context.SetOpenIdConnectRequest(request);

            // client_id is mandatory parameter and MUST cause an error when missing.
            // See http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
            if (string.IsNullOrEmpty(request.ClientId)) {
                return await SendErrorPageAsync(new OpenIdConnectMessage {
                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = "client_id was missing"
                });
            }

            // While redirect_uri was not mandatory in OAuth2, this parameter
            // is now declared as REQUIRED and MUST cause an error when missing.
            // See http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
            // To keep AspNet.Security.OpenIdConnect.Server compatible with pure OAuth2 clients,
            // an error is only returned if the request was made by an OpenID Connect client.
            if (string.IsNullOrEmpty(request.RedirectUri) && request.ContainsScope(OpenIdConnectConstants.Scopes.OpenId)) {
                return await SendErrorPageAsync(new OpenIdConnectMessage {
                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = "redirect_uri must be included when making an OpenID Connect request"
                });
            }

            if (!string.IsNullOrEmpty(request.RedirectUri)) {
                Uri uri;
                if (!Uri.TryCreate(request.RedirectUri, UriKind.Absolute, out uri)) {
                    // redirect_uri MUST be an absolute URI.
                    // See http://tools.ietf.org/html/rfc6749#section-3.1.2
                    // and http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
                    return await SendErrorPageAsync(new OpenIdConnectMessage {
                        Error = OpenIdConnectConstants.Errors.InvalidRequest,
                        ErrorDescription = "redirect_uri must be absolute"
                    });
                }

                else if (!string.IsNullOrEmpty(uri.Fragment)) {
                    // redirect_uri MUST NOT include a fragment component.
                    // See http://tools.ietf.org/html/rfc6749#section-3.1.2
                    // and http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
                    return await SendErrorPageAsync(new OpenIdConnectMessage {
                        Error = OpenIdConnectConstants.Errors.InvalidRequest,
                        ErrorDescription = "redirect_uri must not include a fragment"
                    });
                }

                else if (!Options.AllowInsecureHttp && string.Equals(uri.Scheme, "http", StringComparison.OrdinalIgnoreCase)) {
                    // redirect_uri SHOULD require the use of TLS
                    // http://tools.ietf.org/html/rfc6749#section-3.1.2.1
                    // and http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
                    return await SendErrorPageAsync(new OpenIdConnectMessage {
                        Error = OpenIdConnectConstants.Errors.InvalidRequest,
                        ErrorDescription = "redirect_uri does not meet the security requirements"
                    });
                }
            }

            var clientNotification = new ValidateClientRedirectUriNotification(Context, Options, request);
            await Options.Provider.ValidateClientRedirectUri(clientNotification);

            if (!clientNotification.IsValidated) {
                // Remove the unvalidated redirect_uri
                // from the authorization request.
                request.RedirectUri = null;

                // Update the authorization request in the ASP.NET context.
                Context.SetOpenIdConnectRequest(request);

                Logger.LogVerbose("Unable to validate client information");

                return await SendErrorPageAsync(new OpenIdConnectMessage {
                    Error = clientNotification.Error ?? OpenIdConnectConstants.Errors.InvalidClient,
                    ErrorDescription = clientNotification.ErrorDescription,
                    ErrorUri = clientNotification.ErrorUri
                });
            }

            if (string.IsNullOrEmpty(request.ResponseType)) {
                Logger.LogVerbose("Authorization request missing required response_type parameter");

                return await SendErrorRedirectAsync(request, new OpenIdConnectMessage {
                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = "response_type parameter missing",
                    RedirectUri = request.RedirectUri,
                    State = request.State
                });
            }

            else if (!request.IsNoneResponseType() && !request.IsAuthorizationCodeResponseType() &&
                     !request.IsImplicitResponseType() && !request.IsHybridResponseType()) {
                Logger.LogVerbose("Authorization request contains unsupported response_type parameter");

                return await SendErrorRedirectAsync(request, new OpenIdConnectMessage {
                    Error = OpenIdConnectConstants.Errors.UnsupportedResponseType,
                    ErrorDescription = "response_type unsupported",
                    RedirectUri = request.RedirectUri,
                    State = request.State
                });
            }

            else if (!request.IsFormPostResponseMode() && !request.IsFragmentResponseMode() && !request.IsQueryResponseMode()) {
                Logger.LogVerbose("Authorization request contains unsupported response_mode parameter");

                return await SendErrorRedirectAsync(request, new OpenIdConnectMessage {
                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = "response_mode unsupported",
                    RedirectUri = request.RedirectUri,
                    State = request.State
                });
            }

            // response_mode=query (explicit or not) and a response_type containing id_token
            // or token are not considered as a safe combination and MUST be rejected.
            // See http://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#Security
            else if (request.IsQueryResponseMode() && (request.ContainsResponseType(OpenIdConnectConstants.ResponseTypes.IdToken) ||
                                                       request.ContainsResponseType(OpenIdConnectConstants.ResponseTypes.Token))) {
                Logger.LogVerbose("Authorization request contains unsafe response_type/response_mode combination");

                return await SendErrorRedirectAsync(request, new OpenIdConnectMessage {
                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = "response_type/response_mode combination unsupported",
                    RedirectUri = request.RedirectUri,
                    State = request.State
                });
            }

            // Reject OpenID Connect implicit/hybrid requests missing the mandatory nonce parameter.
            // See http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest,
            // http://openid.net/specs/openid-connect-implicit-1_0.html#RequestParameters
            // and http://openid.net/specs/openid-connect-core-1_0.html#HybridIDToken.
            else if (string.IsNullOrEmpty(request.Nonce) && request.ContainsScope(OpenIdConnectConstants.Scopes.OpenId) &&
                                                           (request.IsImplicitResponseType() || request.IsHybridResponseType())) {
                Logger.LogVerbose("The 'nonce' parameter was missing");

                return await SendErrorRedirectAsync(request, new OpenIdConnectMessage {
                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = "nonce parameter missing",
                    RedirectUri = request.RedirectUri,
                    State = request.State
                });
            }

			// Reject requests containing the id_token response_mode if no openid scope has been received.
            else if (request.ContainsResponseType(OpenIdConnectConstants.ResponseTypes.IdToken) &&
                    !request.ContainsScope(OpenIdConnectConstants.Scopes.OpenId)) {
                Logger.LogVerbose("The 'openid' scope part was missing");

                return await SendErrorRedirectAsync(request, new OpenIdConnectMessage {
                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = "openid scope missing",
                    RedirectUri = request.RedirectUri,
                    State = request.State
                });
            }

            // Reject requests containing the code response_mode if the token endpoint has been disabled.
            else if (request.ContainsResponseType(OpenIdConnectConstants.ResponseTypes.Code) &&
                    !Options.TokenEndpointPath.HasValue) {
                Logger.LogVerbose("Authorization request contains the disabled code response_type");

                return await SendErrorRedirectAsync(request, new OpenIdConnectMessage {
                    Error = OpenIdConnectConstants.Errors.UnsupportedResponseType,
                    ErrorDescription = "response_type=code is not supported by this server",
                    RedirectUri = request.RedirectUri,
                    State = request.State
                });
            }

            // Reject requests containing the id_token response_mode if no signing credentials have been provided.
            else if (request.ContainsResponseType(OpenIdConnectConstants.ResponseTypes.IdToken) &&
                     Options.SigningCredentials == null) {
                Logger.LogVerbose("Authorization request contains the disabled id_token response_type");

                return await SendErrorRedirectAsync(request, new OpenIdConnectMessage {
                    Error = OpenIdConnectConstants.Errors.UnsupportedResponseType,
                    ErrorDescription = "response_type=id_token is not supported by this server",
                    RedirectUri = request.RedirectUri,
                    State = request.State
                });
            }

            var validationNotification = new ValidateAuthorizationRequestNotification(Context, Options, request, clientNotification);
            await Options.Provider.ValidateAuthorizationRequest(validationNotification);

            // Stop processing the request if Validated was not called.
            if (!validationNotification.IsValidated) {
                return await SendErrorRedirectAsync(request, new OpenIdConnectMessage {
                    Error = validationNotification.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = validationNotification.ErrorDescription,
                    ErrorUri = validationNotification.ErrorUri,
                    RedirectUri = request.RedirectUri,
                    State = request.State
                });
            }

            // Generate a new 256-bits identifier and associate it with the authorization request.
            identifier = Base64UrlEncoder.Encode(GenerateKey(length: 256 / 8));
            request.SetUniqueIdentifier(identifier);

            using (var stream = new MemoryStream())
            using (var writer = new BinaryWriter(stream)) {
                writer.Write(/* version: */ 1);
                writer.Write(request.Parameters.Count);

                foreach (var parameter in request.Parameters) {
                    writer.Write(parameter.Key);
                    writer.Write(parameter.Value);
                }

                // Store the authorization request in the distributed cache.
                await Options.Cache.SetAsync(request.GetUniqueIdentifier(), options => {
                    options.SetAbsoluteExpiration(TimeSpan.FromHours(1));

                    return stream.ToArray();
                });
            }

            var notification = new AuthorizationEndpointNotification(Context, Options, request);
            await Options.Provider.AuthorizationEndpoint(notification);

            // Update the authorization request in the ASP.NET context.
            Context.SetOpenIdConnectRequest(request);

            if (notification.HandledResponse) {
                return true;
            }

            return false;
        }

        protected override async Task HandleSignInAsync(SignInContext context) {
            // request may be null when no authorization request has been received
            // or has been already handled by InvokeAuthorizationEndpointAsync.
            var request = Context.GetOpenIdConnectRequest();
            if (request == null) {
                return;
            }

            // Stop processing the request if there's no response grant that matches
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

            // redirect_uri is added to the response message since it's not a mandatory parameter
            // in OAuth 2.0 and can be set or replaced from the ValidateClientRedirectUri notification.
            var response = new OpenIdConnectMessage {
                RedirectUri = request.RedirectUri,
                State = request.State
            };

            // Associate client_id with all subsequent tickets.
            context.Properties[OpenIdConnectConstants.Extra.ClientId] = request.ClientId;

            if (!string.IsNullOrEmpty(request.RedirectUri)) {
                // Keep the original redirect_uri parameter for later comparison.
                context.Properties[OpenIdConnectConstants.Extra.RedirectUri] = request.RedirectUri;
            }

            if (!string.IsNullOrEmpty(request.Resource)) {
                // Keep the original resource parameter for later comparison.
                context.Properties[OpenIdConnectConstants.Extra.Resource] = request.Resource;
            }

            if (!string.IsNullOrEmpty(request.Scope)) {
                // Keep the original scope parameter for later comparison.
                context.Properties[OpenIdConnectConstants.Extra.Scope] = request.Scope;
            }

            // Determine whether an authorization code should be returned
            // and invoke CreateAuthorizationCodeAsync if necessary.
            if (request.ContainsResponseType(OpenIdConnectConstants.ResponseTypes.Code)) {
                // Make sure to create a copy of the authentication properties
                // to avoid modifying the properties set on the original ticket.
                var properties = new AuthenticationProperties(context.Properties).Copy();

                response.Code = await CreateAuthorizationCodeAsync(context.Principal, properties, request, response);

                // Ensure that an authorization code is issued to avoid returning an invalid response.
                // See http://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#Combinations
                if (string.IsNullOrEmpty(response.Code)) {
                    Logger.LogError("CreateAuthorizationCodeAsync returned no authorization code");

                    await SendErrorRedirectAsync(request, new OpenIdConnectMessage {
                        Error = OpenIdConnectConstants.Errors.ServerError,
                        ErrorDescription = "no valid authorization code was issued",
                        RedirectUri = request.RedirectUri,
                        State = request.State
                    });

                    return;
                }
            }

            // Determine whether an identity token should be returned
            // and invoke CreateIdentityTokenAsync if necessary.
            if (request.ContainsResponseType(OpenIdConnectConstants.ResponseTypes.IdToken)) {
                // Make sure to create a copy of the authentication properties
                // to avoid modifying the properties set on the original ticket.
                var properties = new AuthenticationProperties(context.Properties).Copy();

                response.IdToken = await CreateIdentityTokenAsync(context.Principal, properties, request, response);

                // Ensure that an identity token is issued to avoid returning an invalid response.
                // See http://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#Combinations
                if (string.IsNullOrEmpty(response.IdToken)) {
                    Logger.LogError("CreateIdentityTokenAsync returned no identity token.");

                    await SendErrorRedirectAsync(request, new OpenIdConnectMessage {
                        Error = OpenIdConnectConstants.Errors.ServerError,
                        ErrorDescription = "no valid identity token was issued",
                        RedirectUri = request.RedirectUri,
                        State = request.State
                    });

                    return;
                }
            }

            // Determine whether an access token should be returned
            // and invoke CreateAccessTokenAsync if necessary.
            if (request.ContainsResponseType(OpenIdConnectConstants.ResponseTypes.Token)) {
                // Make sure to create a copy of the authentication properties
                // to avoid modifying the properties set on the original ticket.
                var properties = new AuthenticationProperties(context.Properties).Copy();

                response.TokenType = OpenIdConnectConstants.TokenTypes.Bearer;
                response.AccessToken = await CreateAccessTokenAsync(context.Principal, properties, request, response);

                // Ensure that an access token is issued to avoid returning an invalid response.
                // See http://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#Combinations
                if (string.IsNullOrEmpty(response.AccessToken)) {
                    Logger.LogError("CreateAccessTokenAsync returned no access token.");

                    await SendErrorRedirectAsync(request, new OpenIdConnectMessage {
                        Error = OpenIdConnectConstants.Errors.ServerError,
                        ErrorDescription = "no valid access token was issued",
                        RedirectUri = request.RedirectUri,
                        State = request.State
                    });

                    return;
                }

                // properties.ExpiresUtc is automatically set by CreateAccessTokenAsync but the end user
                // is free to set a null value directly in the CreateAccessToken notification.
                if (properties.ExpiresUtc.HasValue && properties.ExpiresUtc > Options.SystemClock.UtcNow) {
                    var lifetime = properties.ExpiresUtc.Value - Options.SystemClock.UtcNow;
                    var expiration = (long) (lifetime.TotalSeconds + .5);

                    response.ExpiresIn = expiration.ToString(CultureInfo.InvariantCulture);
                }
            }

            // Remove the OpenID Connect request from the distributed cache.
            var identifier = request.GetUniqueIdentifier();
            if (!string.IsNullOrEmpty(identifier)) {
                await Options.Cache.RemoveAsync(identifier);
            }

            var notification = new AuthorizationEndpointResponseNotification(Context, Options, request, response);
            await Options.Provider.AuthorizationEndpointResponse(notification);

            if (notification.HandledResponse) {
                return;
            }

            await ApplyAuthorizationResponseAsync(request, response);
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
            // set or replaced from the ValidateClientLogoutRedirectUri notification.
            var response = new OpenIdConnectMessage {
                PostLogoutRedirectUri = request.PostLogoutRedirectUri,
                State = request.State
            };

            var notification = new LogoutEndpointResponseNotification(Context, Options, request, response);
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

        protected override async Task FinishResponseAsync() {
            // Stop processing the request if no OpenID Connect
            // message has been found in the current context.
            var request = Context.GetOpenIdConnectRequest();
            if (request == null) {
                return;
            }

            // Don't apply any modification to the response if no OpenID Connect
            // message has been explicitly created by the inner application.
            var response = Context.GetOpenIdConnectResponse();
            if (response == null) {
                return;
            }

            // Successful authorization responses are directly applied by
            // HandleSignInAsync: only error responses should be handled at this stage.
            if (string.IsNullOrEmpty(response.Error)) {
                return;
            }

            await SendErrorRedirectAsync(request, response);
        }

        private async Task<bool> ApplyAuthorizationResponseAsync(OpenIdConnectMessage request, OpenIdConnectMessage response) {
            if (request.IsFormPostResponseMode()) {
                using (var buffer = new MemoryStream())
                using (var writer = new StreamWriter(buffer)) {
                    writer.WriteLine("<!doctype html>");
                    writer.WriteLine("<html>");
                    writer.WriteLine("<body>");

                    // While the redirect_uri parameter should be guarded against unknown values
                    // by IOpenIdConnectServerProvider.ValidateClientRedirectUri,
                    // it's still safer to encode it to avoid cross-site scripting attacks
                    // if the authorization server has a relaxed policy concerning redirect URIs.
                    writer.WriteLine("<form name='form' method='post' action='" + Options.HtmlEncoder.HtmlEncode(response.RedirectUri) + "'>");

                    foreach (var parameter in response.Parameters) {
                        // Don't include redirect_uri in the form.
                        if (string.Equals(parameter.Key, OpenIdConnectParameterNames.RedirectUri, StringComparison.Ordinal)) {
                            continue;
                        }

                        var name = Options.HtmlEncoder.HtmlEncode(parameter.Key);
                        var value = Options.HtmlEncoder.HtmlEncode(parameter.Value);

                        writer.WriteLine("<input type='hidden' name='" + name + "' value='" + value + "' />");
                    }

                    writer.WriteLine("<noscript>Click here to finish the authorization process: <input type='submit' /></noscript>");
                    writer.WriteLine("</form>");
                    writer.WriteLine("<script>document.form.submit();</script>");
                    writer.WriteLine("</body>");
                    writer.WriteLine("</html>");
                    writer.Flush();

                    Response.ContentLength = buffer.Length;
                    Response.ContentType = "text/html;charset=UTF-8";

                    buffer.Seek(offset: 0, loc: SeekOrigin.Begin);
                    await buffer.CopyToAsync(Response.Body, 4096, Context.RequestAborted);

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

                    location = QueryHelpers.AddQueryString(location, parameter.Key, parameter.Value);
                }

                Response.Redirect(location);
                return true;
            }

            return false;
        }

        private async Task InvokeConfigurationEndpointAsync() {
            var notification = new ConfigurationEndpointNotification(Context, Options);
            notification.Issuer = Context.GetIssuer(Options);

            // Metadata requests must be made via GET.
            // See http://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationRequest
            if (!string.Equals(Request.Method, "GET", StringComparison.OrdinalIgnoreCase)) {
                Logger.LogError(string.Format(CultureInfo.InvariantCulture,
                    "Configuration endpoint: invalid method '{0}' used", Request.Method));
                return;
            }

            if (Options.AuthorizationEndpointPath.HasValue) {
                // Set the default endpoints concatenating the current path base and Options.*EndpointPath.
                notification.AuthorizationEndpoint = notification.Issuer.AddPath(Options.AuthorizationEndpointPath);
            }

            // While the jwks_uri parameter is in principle mandatory, many OIDC clients are known
            // to work in a degraded mode when this parameter is not provided in the JSON response.
            // Making it mandatory in AspNet.Security.OpenIdConnect.Server would prevent the end developer from
            // using custom security keys and manage himself the token validation parameters in the OIDC client.
            // To avoid this issue, the jwks_uri parameter is only added to the response when the JWKS endpoint
            // is believed to provide a valid response, which is the case with asymmetric keys supporting RSA-SHA256.
            // See http://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
            if (Options.CryptographyEndpointPath.HasValue &&
                Options.SigningCredentials != null &&
                Options.SigningCredentials.SigningKey is AsymmetricSecurityKey &&
                Options.SigningCredentials.SigningKey.IsSupportedAlgorithm(SecurityAlgorithms.RsaSha256Signature)) {
                notification.CryptographyEndpoint = notification.Issuer.AddPath(Options.CryptographyEndpointPath);
            }

            if (Options.TokenEndpointPath.HasValue) {
                notification.TokenEndpoint = notification.Issuer.AddPath(Options.TokenEndpointPath);
            }

            if (Options.LogoutEndpointPath.HasValue) {
                notification.LogoutEndpoint = notification.Issuer.AddPath(Options.LogoutEndpointPath);
            }

            if (Options.AuthorizationEndpointPath.HasValue) {
                // Only expose the implicit grant type if the token
                // endpoint has not been explicitly disabled.
                notification.GrantTypes.Add(OpenIdConnectConstants.GrantTypes.Implicit);
            }

            if (Options.TokenEndpointPath.HasValue) {
                // Only expose the authorization code and refresh token grant types
                // if the token endpoint has not been explicitly disabled.
                notification.GrantTypes.Add(OpenIdConnectConstants.GrantTypes.AuthorizationCode);
                notification.GrantTypes.Add(OpenIdConnectConstants.GrantTypes.RefreshToken);
            }

            notification.ResponseModes.Add(OpenIdConnectConstants.ResponseModes.FormPost);
            notification.ResponseModes.Add(OpenIdConnectConstants.ResponseModes.Fragment);
            notification.ResponseModes.Add(OpenIdConnectConstants.ResponseModes.Query);

            notification.ResponseTypes.Add(OpenIdConnectConstants.ResponseTypes.Token);

            // Only expose response types containing id_token when
            // signing credentials have been explicitly provided.
            if (Options.SigningCredentials != null) {
                notification.ResponseTypes.Add(OpenIdConnectConstants.ResponseTypes.IdToken);
                notification.ResponseTypes.Add(
                    OpenIdConnectConstants.ResponseTypes.IdToken + ' ' +
                    OpenIdConnectConstants.ResponseTypes.Token);
            }

            // Only expose response types containing code when
            // the token endpoint has not been explicitly disabled.
            if (Options.TokenEndpointPath.HasValue) {
                notification.ResponseTypes.Add(OpenIdConnectConstants.ResponseTypes.Code);

                notification.ResponseTypes.Add(
                    OpenIdConnectConstants.ResponseTypes.Code + ' ' +
                    OpenIdConnectConstants.ResponseTypes.Token);

                // Only expose response types containing id_token when
                // signing credentials have been explicitly provided.
                if (Options.SigningCredentials != null) {
                    notification.ResponseTypes.Add(
                        OpenIdConnectConstants.ResponseTypes.Code + ' ' +
                        OpenIdConnectConstants.ResponseTypes.IdToken);

                    notification.ResponseTypes.Add(
                        OpenIdConnectConstants.ResponseTypes.Code + ' ' +
                        OpenIdConnectConstants.ResponseTypes.IdToken + ' ' +
                        OpenIdConnectConstants.ResponseTypes.Token);
                }
            }

            notification.Scopes.Add(OpenIdConnectConstants.Scopes.OpenId);

            notification.SubjectTypes.Add(OpenIdConnectConstants.SubjectTypes.Public);
            notification.SubjectTypes.Add(OpenIdConnectConstants.SubjectTypes.Pairwise);

            notification.SigningAlgorithms.Add(OpenIdConnectConstants.Algorithms.RS256);

            await Options.Provider.ConfigurationEndpoint(notification);

            if (notification.HandledResponse) {
                return;
            }

            var payload = new JObject();

            payload.Add(OpenIdConnectConstants.Metadata.Issuer, notification.Issuer);

            if (!string.IsNullOrEmpty(notification.AuthorizationEndpoint)) {
                payload.Add(OpenIdConnectConstants.Metadata.AuthorizationEndpoint, notification.AuthorizationEndpoint);
            }

            if (!string.IsNullOrEmpty(notification.TokenEndpoint)) {
                payload.Add(OpenIdConnectConstants.Metadata.TokenEndpoint, notification.TokenEndpoint);
            }

            if (!string.IsNullOrEmpty(notification.LogoutEndpoint)) {
                payload.Add(OpenIdConnectConstants.Metadata.EndSessionEndpoint, notification.LogoutEndpoint);
            }

            if (!string.IsNullOrEmpty(notification.CryptographyEndpoint)) {
                payload.Add(OpenIdConnectConstants.Metadata.JwksUri, notification.CryptographyEndpoint);
            }

            payload.Add(OpenIdConnectConstants.Metadata.GrantTypesSupported,
                JArray.FromObject(notification.GrantTypes));

            payload.Add(OpenIdConnectConstants.Metadata.ResponseModesSupported,
                JArray.FromObject(notification.ResponseModes));

            payload.Add(OpenIdConnectConstants.Metadata.ResponseTypesSupported,
                JArray.FromObject(notification.ResponseTypes));

            payload.Add(OpenIdConnectConstants.Metadata.SubjectTypesSupported,
                JArray.FromObject(notification.SubjectTypes));

            payload.Add(OpenIdConnectConstants.Metadata.ScopesSupported,
                JArray.FromObject(notification.Scopes));

            payload.Add(OpenIdConnectConstants.Metadata.IdTokenSigningAlgValuesSupported,
                JArray.FromObject(notification.SigningAlgorithms));

            var responseNotification = new ConfigurationEndpointResponseNotification(Context, Options, payload);
            await Options.Provider.ConfigurationEndpointResponse(responseNotification);

            if (responseNotification.HandledResponse) {
                return;
            }

            using (var buffer = new MemoryStream())
            using (var writer = new JsonTextWriter(new StreamWriter(buffer))) {
                payload.WriteTo(writer);
                writer.Flush();

                Response.ContentLength = buffer.Length;
                Response.ContentType = "application/json;charset=UTF-8";

                buffer.Seek(offset: 0, loc: SeekOrigin.Begin);
                await buffer.CopyToAsync(Response.Body, 4096, Context.RequestAborted);
            }
        }

        private async Task InvokeCryptographyEndpointAsync() {
            var notification = new CryptographyEndpointNotification(Context, Options);

            // Metadata requests must be made via GET.
            // See http://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationRequest
            if (!string.Equals(Request.Method, "GET", StringComparison.OrdinalIgnoreCase)) {
                Logger.LogError(string.Format(CultureInfo.InvariantCulture,
                    "Cryptography endpoint: invalid method '{0}' used", Request.Method));
                return;
            }

            if (Options.SigningCredentials == null) {
                Logger.LogError("Cryptography endpoint: no signing credentials provided. " +
                    "Make sure valid credentials are assigned to Options.SigningCredentials.");
                return;
            }

            // Skip processing the metadata request if no supported key can be found.
            var asymmetricSecurityKey = Options.SigningCredentials.SigningKey as AsymmetricSecurityKey;
            if (asymmetricSecurityKey == null) {
                Logger.LogError(string.Format(CultureInfo.InvariantCulture,
                    "Cryptography endpoint: invalid signing key registered. " +
                    "Make sure to provide an asymmetric security key deriving from '{0}'.",
                    typeof(AsymmetricSecurityKey).FullName));
                return;
            }

            if (!asymmetricSecurityKey.IsSupportedAlgorithm(SecurityAlgorithms.RsaSha256Signature)) {
                Logger.LogError(string.Format(CultureInfo.InvariantCulture,
                    "Cryptography endpoint: invalid signing key registered. " +
                    "Make sure to provide a '{0}' instance exposing " +
                    "an asymmetric security key supporting the '{1}' algorithm.",
                    typeof(SigningCredentials).Name, SecurityAlgorithms.RsaSha256Signature));
                return;
            }

            // Determine whether the security key is an asymmetric key embedded in a X.509 certificate.
            var x509SecurityKey = asymmetricSecurityKey as X509SecurityKey;
            if (x509SecurityKey != null) {
                // Create a new JSON Web Key exposing the
                // certificate instead of its public RSA key.
                notification.Keys.Add(new JsonWebKey {
                    Kty = JsonWebAlgorithmsKeyTypes.RSA,
                    Alg = JwtAlgorithms.RSA_SHA256,
                    Use = JsonWebKeyUseNames.Sig,

                    // x5t must be base64url-encoded.
                    // See http://tools.ietf.org/html/draft-ietf-jose-json-web-key-31#section-4.8
                    X5t = Base64UrlEncoder.Encode(x509SecurityKey.Certificate.GetCertHash()),

                    // Unlike E or N, the certificates contained in x5c
                    // must be base64-encoded and not base64url-encoded.
                    // See http://tools.ietf.org/html/draft-ietf-jose-json-web-key-31#section-4.7
                    X5c = { Convert.ToBase64String(x509SecurityKey.Certificate.RawData) }
                });
            }

            else {
                var rsaSecurityKey = asymmetricSecurityKey as RsaSecurityKey;
                if (rsaSecurityKey != null) {
                    // Export the RSA public key.
                    notification.Keys.Add(new JsonWebKey {
                        Kty = JsonWebAlgorithmsKeyTypes.RSA,
                        Alg = JwtAlgorithms.RSA_SHA256,
                        Use = JsonWebKeyUseNames.Sig,

                        // Both E and N must be base64url-encoded.
                        // See http://tools.ietf.org/html/draft-ietf-jose-json-web-key-31#appendix-A.1
                        E = Base64UrlEncoder.Encode(rsaSecurityKey.Parameters.Exponent),
                        N = Base64UrlEncoder.Encode(rsaSecurityKey.Parameters.Modulus)
                    });
                }
            }

            await Options.Provider.CryptographyEndpoint(notification);

            if (notification.HandledResponse) {
                return;
            }

            // Ensure at least one key has been added to context.Keys.
            if (!notification.Keys.Any()) {
                Logger.LogError("Cryptography endpoint: no JSON Web Key found.");
                return;
            }

            var payload = new JObject();
            var keys = new JArray();

            foreach (var key in notification.Keys) {
                var item = new JObject();

                // Ensure a key type has been provided.
                // See http://tools.ietf.org/html/draft-ietf-jose-json-web-key-31#section-4.1
                if (string.IsNullOrEmpty(key.Kty)) {
                    Logger.LogWarning("Cryptography endpoint: a JSON Web Key didn't " +
                        "contain the mandatory 'Kty' parameter and has been ignored.");
                    continue;
                }

                // Create a dictionary associating the
                // JsonWebKey components with their values.
                var parameters = new Dictionary<string, string> {
                    [JsonWebKeyParameterNames.Kty] = key.Kty,
                    [JsonWebKeyParameterNames.Alg] = key.Alg,
                    [JsonWebKeyParameterNames.E] = key.E,
                    [JsonWebKeyParameterNames.Kid] = key.Kid,
                    [JsonWebKeyParameterNames.N] = key.N,
                    [JsonWebKeyParameterNames.Use] = key.Use,
                    [JsonWebKeyParameterNames.X5t] = key.X5t,
                    [JsonWebKeyParameterNames.X5u] = key.X5u,
                };

                foreach (var parameter in parameters) {
                    if (!string.IsNullOrEmpty(parameter.Value)) {
                        item.Add(parameter.Key, parameter.Value);
                    }
                }

                if (key.KeyOps.Any()) {
                    item.Add(JsonWebKeyParameterNames.KeyOps, JArray.FromObject(key.KeyOps));
                }

                if (key.X5c.Any()) {
                    item.Add(JsonWebKeyParameterNames.X5c, JArray.FromObject(key.X5c));
                }

                keys.Add(item);
            }

            payload.Add(JsonWebKeyParameterNames.Keys, keys);

            var responseNotification = new CryptographyEndpointResponseNotification(Context, Options, payload);
            await Options.Provider.CryptographyEndpointResponse(responseNotification);

            if (responseNotification.HandledResponse) {
                return;
            }

            using (var buffer = new MemoryStream())
            using (var writer = new JsonTextWriter(new StreamWriter(buffer))) {
                payload.WriteTo(writer);
                writer.Flush();

                Response.ContentLength = buffer.Length;
                Response.ContentType = "application/json;charset=UTF-8";

                buffer.Seek(offset: 0, loc: SeekOrigin.Begin);
                await buffer.CopyToAsync(Response.Body, 4096, Context.RequestAborted);
            }
        }

        private async Task InvokeTokenEndpointAsync() {
            if (!string.Equals(Request.Method, "POST", StringComparison.OrdinalIgnoreCase)) {
                await SendErrorPayloadAsync(new OpenIdConnectMessage {
                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = "A malformed token request has been received: make sure to use POST."
                });

                return;
            }

            // See http://openid.net/specs/openid-connect-core-1_0.html#FormSerialization
            if (string.IsNullOrEmpty(Request.ContentType)) {
                await SendErrorPayloadAsync(new OpenIdConnectMessage {
                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = "A malformed token request has been received: " +
                        "the mandatory 'Content-Type' header was missing from the POST request."
                });

                return;
            }

            // May have media/type; charset=utf-8, allow partial match.
            if (!Request.ContentType.StartsWith("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase)) {
                await SendErrorPayloadAsync(new OpenIdConnectMessage {
                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = "A malformed token request has been received: " +
                        "the 'Content-Type' header contained an unexcepted value. " +
                        "Make sure to use 'application/x-www-form-urlencoded'."
                });

                return;
            }

            var request = new OpenIdConnectMessage(await Request.ReadFormAsync()) {
                RequestType = OpenIdConnectRequestType.TokenRequest
            };

            // When client_id and client_secret are both null, try to extract them from the Authorization header.
            // See http://tools.ietf.org/html/rfc6749#section-2.3.1 and
            // http://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication
            if (string.IsNullOrEmpty(request.ClientId) && string.IsNullOrEmpty(request.ClientSecret)) {
                var header = Request.Headers.Get("Authorization");
                if (!string.IsNullOrEmpty(header) && header.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase)) {
                    try {
                        var value = header.Substring("Basic ".Length).Trim();
                        var data = Encoding.UTF8.GetString(Convert.FromBase64String(value));

                        var index = data.IndexOf(':');
                        if (index >= 0) {
                            request.ClientId = data.Substring(0, index);
                            request.ClientSecret = data.Substring(index + 1);
                        }
                    }

                    catch (FormatException) { }
                    catch (ArgumentException) { }
                }
            }

            var clientNotification = new ValidateClientAuthenticationNotification(Context, Options, request);
            await Options.Provider.ValidateClientAuthentication(clientNotification);

            if (!clientNotification.IsValidated) {
                Logger.LogError("clientID is not valid.");

                if (!clientNotification.HasError) {
                    clientNotification.SetError(OpenIdConnectConstants.Errors.InvalidClient);
                }

                await SendErrorPayloadAsync(new OpenIdConnectMessage {
                    Error = clientNotification.Error,
                    ErrorDescription = clientNotification.ErrorDescription,
                    ErrorUri = clientNotification.ErrorUri
                });

                return;
            }

            var validatingContext = new ValidateTokenRequestNotification(Context, Options, request, clientNotification);

            AuthenticationTicket ticket = null;
            if (request.IsAuthorizationCodeGrantType()) {
                // Authorization Code Grant http://tools.ietf.org/html/rfc6749#section-4.1
                // Access Token Request http://tools.ietf.org/html/rfc6749#section-4.1.3
                ticket = await InvokeTokenEndpointAuthorizationCodeGrantAsync(validatingContext);
            }

            else if (request.IsPasswordGrantType()) {
                // Resource Owner Password Credentials Grant http://tools.ietf.org/html/rfc6749#section-4.3
                // Access Token Request http://tools.ietf.org/html/rfc6749#section-4.3.2
                ticket = await InvokeTokenEndpointResourceOwnerPasswordCredentialsGrantAsync(validatingContext);
            }

            else if (request.IsClientCredentialsGrantType()) {
                // Client Credentials Grant http://tools.ietf.org/html/rfc6749#section-4.4
                // Access Token Request http://tools.ietf.org/html/rfc6749#section-4.4.2
                ticket = await InvokeTokenEndpointClientCredentialsGrantAsync(validatingContext);
            }

            else if (request.IsRefreshTokenGrantType()) {
                // Refreshing an Access Token
                // http://tools.ietf.org/html/rfc6749#section-6
                ticket = await InvokeTokenEndpointRefreshTokenGrantAsync(validatingContext);
            }

            else if (!string.IsNullOrEmpty(request.GrantType)) {
                // Defining New Authorization Grant Types
                // http://tools.ietf.org/html/rfc6749#section-8.3
                ticket = await InvokeTokenEndpointCustomGrantAsync(validatingContext);
            }

            else {
                // Error Response http://tools.ietf.org/html/rfc6749#section-5.2
                // The authorization grant type is not supported by the
                // authorization server.
                Logger.LogError("grant type is not recognized");
                validatingContext.SetError(OpenIdConnectConstants.Errors.UnsupportedGrantType);
            }

            if (ticket == null) {
                await SendErrorPayloadAsync(new OpenIdConnectMessage {
                    Error = validatingContext.Error,
                    ErrorDescription = validatingContext.ErrorDescription,
                    ErrorUri = validatingContext.ErrorUri
                });

                return;
            }

            var notification = new TokenEndpointNotification(Context, Options, request, ticket);
            await Options.Provider.TokenEndpoint(notification);

            if (notification.HandledResponse) {
                return;
            }

            // Flow the changes made to the ticket.
            ticket = notification.Ticket;

            var response = new OpenIdConnectMessage();

            // Determine whether an identity token should be returned and invoke CreateIdentityTokenAsync if necessary.
            // Note: by default, an identity token is always returned, but the client application can use the response_type
            // parameter to only include specific types of tokens. When this parameter is missing, a token is always generated.
            if (string.IsNullOrEmpty(request.ResponseType) || request.ContainsResponseType(OpenIdConnectConstants.ResponseTypes.IdToken)) {
                // Make sure to create a copy of the authentication properties
                // to avoid modifying the properties set on the original ticket.
                var properties = ticket.Properties.Copy();

                // When the authorization code or the refresh token grant type has been used,
                // properties.IssuedUtc and properties.ExpiresUtc are explicitly set to null
                // to avoid aligning the expiration date of the identity token on the lifetime
                // of the authorization code or the refresh token used by the client application.
                if (request.IsAuthorizationCodeGrantType() || request.IsRefreshTokenGrantType()) {
                    properties.IssuedUtc = properties.ExpiresUtc = null;
                }

                // When sliding expiration is disabled, the identity token added to the response
                // cannot live longer than the refresh token that was used in the token request.
                if (request.IsRefreshTokenGrantType() && !Options.UseSlidingExpiration &&
                    ticket.Properties.ExpiresUtc.HasValue &&
                    ticket.Properties.ExpiresUtc.Value < (Options.SystemClock.UtcNow + Options.IdentityTokenLifetime)) {
                    properties.ExpiresUtc = ticket.Properties.ExpiresUtc;
                }

                response.IdToken = await CreateIdentityTokenAsync(ticket.Principal, properties, request, response);

                // Ensure that an identity token is issued to avoid returning an invalid response, but only if the authorization
                // request was an OpenID Connect request or if the token request contains the explicit "openid" scope.
                // See http://openid.net/specs/openid-connect-core-1_0.html#TokenResponse
                // and http://openid.net/specs/openid-connect-core-1_0.html#RefreshTokenResponse
                if (string.IsNullOrEmpty(response.IdToken) && (request.ContainsScope(OpenIdConnectConstants.Scopes.OpenId) ||
                                                               ticket.ContainsScope(OpenIdConnectConstants.Scopes.OpenId))) {
                    Logger.LogError("CreateIdentityTokenAsync returned no identity token.");

                    await SendErrorPayloadAsync(new OpenIdConnectMessage {
                        Error = OpenIdConnectConstants.Errors.ServerError,
                        ErrorDescription = "no valid identity token was issued"
                    });

                    return;
                }
            }

            // Determine whether an access token should be returned and invoke CreateAccessTokenAsync if necessary.
            // Note: by default, an access token is always returned, but the client application can use the response_type
            // parameter to only include specific types of tokens. When this parameter is missing, a token is always generated.
            if (string.IsNullOrEmpty(request.ResponseType) || request.ContainsResponseType(OpenIdConnectConstants.ResponseTypes.Token)) {
                // Make sure to create a copy of the authentication properties
                // to avoid modifying the properties set on the original ticket.
                var properties = ticket.Properties.Copy();

                // When the authorization code or the refresh token grant type has been used,
                // properties.IssuedUtc and properties.ExpiresUtc are explicitly set to null
                // to avoid aligning the expiration date of the access token on the lifetime
                // of the authorization code or the refresh token used by the client application.
                if (request.IsAuthorizationCodeGrantType() || request.IsRefreshTokenGrantType()) {
                    properties.IssuedUtc = properties.ExpiresUtc = null;
                }

                // When sliding expiration is disabled, the access token added to the response
                // cannot live longer than the refresh token that was used in the token request.
                if (request.IsRefreshTokenGrantType() && !Options.UseSlidingExpiration &&
                    ticket.Properties.ExpiresUtc.HasValue &&
                    ticket.Properties.ExpiresUtc.Value < (Options.SystemClock.UtcNow + Options.AccessTokenLifetime)) {
                    properties.ExpiresUtc = ticket.Properties.ExpiresUtc;
                }

                response.TokenType = OpenIdConnectConstants.TokenTypes.Bearer;
                response.AccessToken = await CreateAccessTokenAsync(ticket.Principal, properties, request, response);

                // Ensure that an access token is issued to avoid returning an invalid response.
                // See http://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#Combinations
                if (string.IsNullOrEmpty(response.AccessToken)) {
                    Logger.LogError("CreateAccessTokenAsync returned no access token.");

                    await SendErrorPayloadAsync(new OpenIdConnectMessage {
                        Error = OpenIdConnectConstants.Errors.ServerError,
                        ErrorDescription = "no valid access token was issued"
                    });

                    return;
                }

                // properties.ExpiresUtc is automatically set by CreateAccessTokenAsync but the end user
                // is free to set a null value directly in the CreateAccessToken notification.
                if (properties.ExpiresUtc.HasValue && properties.ExpiresUtc > Options.SystemClock.UtcNow) {
                    var lifetime = properties.ExpiresUtc.Value - Options.SystemClock.UtcNow;
                    var expiration = (long) (lifetime.TotalSeconds + .5);

                    response.ExpiresIn = expiration.ToString(CultureInfo.InvariantCulture);
                }
            }

            // Determine whether a refresh token should be returned and invoke CreateRefreshTokenAsync if necessary.
            // Note: by default, a refresh token is always returned, but the client application can use the response_type
            // parameter to only include specific types of tokens. When this parameter is missing, a token is always generated.
            if (string.IsNullOrEmpty(request.ResponseType) || request.ContainsResponseType("refresh_token")) {
                // Make sure to create a copy of the authentication properties
                // to avoid modifying the properties set on the original ticket.
                var properties = ticket.Properties.Copy();

                // When the authorization code or the refresh token grant type has been used,
                // properties.IssuedUtc and properties.ExpiresUtc are explicitly set to null
                // to avoid aligning the expiration date of the refresh token on the lifetime
                // of the authorization code or the refresh token used by the client application.
                if (request.IsAuthorizationCodeGrantType() || request.IsRefreshTokenGrantType()) {
                    properties.IssuedUtc = properties.ExpiresUtc = null;
                }

                // When sliding expiration is disabled, the refresh token added to the response
                // cannot live longer than the refresh token that was used in the token request.
                if (request.IsRefreshTokenGrantType() && !Options.UseSlidingExpiration &&
                    ticket.Properties.ExpiresUtc.HasValue &&
                    ticket.Properties.ExpiresUtc.Value < (Options.SystemClock.UtcNow + Options.RefreshTokenLifetime)) {
                    properties.ExpiresUtc = ticket.Properties.ExpiresUtc;
                }

                response.SetRefreshToken(await CreateRefreshTokenAsync(ticket.Principal, properties, request, response));
            }

            var payload = new JObject();

            foreach (var parameter in response.Parameters) {
                payload.Add(parameter.Key, parameter.Value);
            }

            var responseNotification = new TokenEndpointResponseNotification(Context, Options, payload);
            await Options.Provider.TokenEndpointResponse(responseNotification);

            if (responseNotification.HandledResponse) {
                return;
            }

            using (var buffer = new MemoryStream())
            using (var writer = new JsonTextWriter(new StreamWriter(buffer))) {
                payload.WriteTo(writer);
                writer.Flush();

                Response.ContentLength = buffer.Length;
                Response.ContentType = "application/json;charset=UTF-8";

                Response.Headers.Set("Cache-Control", "no-cache");
                Response.Headers.Set("Pragma", "no-cache");
                Response.Headers.Set("Expires", "-1");

                buffer.Seek(offset: 0, loc: SeekOrigin.Begin);
                await buffer.CopyToAsync(Response.Body, 4096, Context.RequestAborted);
            }
        }

        private async Task<AuthenticationTicket> InvokeTokenEndpointAuthorizationCodeGrantAsync(ValidateTokenRequestNotification notification) {
            var ticket = await ReceiveAuthorizationCodeAsync(notification.Request.Code, notification.Request);
            if (ticket == null) {
                Logger.LogError("invalid authorization code");
                notification.SetError(OpenIdConnectConstants.Errors.InvalidGrant);
                return null;
            }

            if (!ticket.Properties.ExpiresUtc.HasValue ||
                 ticket.Properties.ExpiresUtc < Options.SystemClock.UtcNow) {
                Logger.LogError("expired authorization code");
                notification.SetError(OpenIdConnectConstants.Errors.InvalidGrant);
                return null;
            }

            var clientId = ticket.Properties.GetProperty(OpenIdConnectConstants.Extra.ClientId);
            if (string.IsNullOrEmpty(clientId) || !string.Equals(clientId, notification.Request.ClientId, StringComparison.Ordinal)) {
                Logger.LogError("authorization code does not contain matching client_id");
                notification.SetError(OpenIdConnectConstants.Errors.InvalidGrant);
                return null;
            }
            
            string redirectUri;
            if (ticket.Properties.Items.TryGetValue(OpenIdConnectConstants.Extra.RedirectUri, out redirectUri)) {
                ticket.Properties.Items.Remove(OpenIdConnectConstants.Extra.RedirectUri);

                if (!string.Equals(redirectUri, notification.Request.RedirectUri, StringComparison.Ordinal)) {
                    Logger.LogError("authorization code does not contain matching redirect_uri");
                    notification.SetError(OpenIdConnectConstants.Errors.InvalidGrant);
                    return null;
                }
            }

            if (!string.IsNullOrEmpty(notification.Request.Resource)) {
                // When an explicit resource parameter has been included in the token request
                // but was missing from the authorization request, the request MUST rejected.
                var resources = ticket.Properties.GetResources();
                if (!resources.Any()) {
                    Logger.LogError("authorization code request cannot contain a resource");
                    notification.SetError(OpenIdConnectConstants.Errors.InvalidGrant);
                    return null;
                }

                // When an explicit resource parameter has been included in the token request,
                // the authorization server MUST ensure that it doesn't contain resources
                // that were not allowed during the authorization request.
                else if (!resources.ContainsSet(notification.Request.GetResources())) {
                    Logger.LogError("authorization code does not contain matching resource");
                    notification.SetError(OpenIdConnectConstants.Errors.InvalidGrant);
                    return null;
                }
            }

            if (!string.IsNullOrEmpty(notification.Request.Scope)) {
                // When an explicit scope parameter has been included in the token request
                // but was missing from the authorization request, the request MUST rejected.
                var scopes = ticket.Properties.GetScopes();
                if (!scopes.Any()) {
                    Logger.LogError("authorization code request cannot contain a scope");
                    notification.SetError(OpenIdConnectConstants.Errors.InvalidGrant);
                    return null;
                }

                // When an explicit scope parameter has been included in the token request,
                // the authorization server MUST ensure that it doesn't contain scopes
                // that were not allowed during the authorization request.
                else if (!scopes.ContainsSet(notification.Request.GetScopes())) {
                    Logger.LogError("authorization code does not contain matching scope");
                    notification.SetError(OpenIdConnectConstants.Errors.InvalidGrant);
                    return null;
                }
            }

            await Options.Provider.ValidateTokenRequest(notification);

            var context = new GrantAuthorizationCodeNotification(Context, Options, notification.Request, ticket);

            if (notification.IsValidated) {
                await Options.Provider.GrantAuthorizationCode(context);
            }

            return ReturnOutcome(notification, context, context.Ticket, OpenIdConnectConstants.Errors.InvalidGrant);
        }

        private async Task<AuthenticationTicket> InvokeTokenEndpointResourceOwnerPasswordCredentialsGrantAsync(ValidateTokenRequestNotification notification) {
            await Options.Provider.ValidateTokenRequest(notification);

            var context = new GrantResourceOwnerCredentialsNotification(Context, Options, notification.Request);

            if (notification.IsValidated) {
                await Options.Provider.GrantResourceOwnerCredentials(context);
            }

            return ReturnOutcome(notification, context, context.Ticket, OpenIdConnectConstants.Errors.InvalidGrant);
        }

        private async Task<AuthenticationTicket> InvokeTokenEndpointClientCredentialsGrantAsync(ValidateTokenRequestNotification notification) {
            await Options.Provider.ValidateTokenRequest(notification);

            if (!notification.IsValidated) {
                return null;
            }

            var context = new GrantClientCredentialsNotification(Context, Options, notification.Request);
            await Options.Provider.GrantClientCredentials(context);

            return ReturnOutcome(notification, context, context.Ticket, OpenIdConnectConstants.Errors.UnauthorizedClient);
        }

        private async Task<AuthenticationTicket> InvokeTokenEndpointRefreshTokenGrantAsync(ValidateTokenRequestNotification notification) {
            var ticket = await ReceiveRefreshTokenAsync(notification.Request.GetRefreshToken(), notification.Request);
            if (ticket == null) {
                Logger.LogError("invalid refresh token");
                notification.SetError(OpenIdConnectConstants.Errors.InvalidGrant);
                return null;
            }

            if (!ticket.Properties.ExpiresUtc.HasValue ||
                 ticket.Properties.ExpiresUtc < Options.SystemClock.UtcNow) {
                Logger.LogError("expired refresh token");
                notification.SetError(OpenIdConnectConstants.Errors.InvalidGrant);
                return null;
            }

            var clientId = ticket.Properties.GetProperty(OpenIdConnectConstants.Extra.ClientId);
            if (string.IsNullOrEmpty(clientId) || !string.Equals(clientId, notification.Request.ClientId, StringComparison.Ordinal)) {
                Logger.LogError("refresh token does not contain matching client_id");
                notification.SetError(OpenIdConnectConstants.Errors.InvalidGrant);
                return null;
            }

            if (!string.IsNullOrEmpty(notification.Request.Resource)) {
                // When an explicit resource parameter has been included in the token request
                // but was missing from the authorization request, the request MUST rejected.
                var resources = ticket.Properties.GetResources();
                if (!resources.Any()) {
                    Logger.LogError("refresh token request cannot contain a resource");
                    notification.SetError(OpenIdConnectConstants.Errors.InvalidGrant);
                    return null;
                }

                // When an explicit resource parameter has been included in the token request,
                // the authorization server MUST ensure that it doesn't contain resources
                // that were not allowed during the authorization request.
                else if (!resources.ContainsSet(notification.Request.GetResources())) {
                    Logger.LogError("refresh token does not contain matching resource");
                    notification.SetError(OpenIdConnectConstants.Errors.InvalidGrant);
                    return null;
                }
            }

            if (!string.IsNullOrEmpty(notification.Request.Scope)) {
                // When an explicit scope parameter has been included in the token request
                // but was missing from the authorization request, the request MUST rejected.
                var scopes = ticket.Properties.GetScopes();
                if (!scopes.Any()) {
                    Logger.LogError("refresh token request cannot contain a scope");
                    notification.SetError(OpenIdConnectConstants.Errors.InvalidGrant);
                    return null;
                }

                // When an explicit scope parameter has been included in the token request,
                // the authorization server MUST ensure that it doesn't contain scopes
                // that were not allowed during the authorization request.
                else if (!scopes.ContainsSet(notification.Request.GetScopes())) {
                    Logger.LogError("refresh token does not contain matching scope");
                    notification.SetError(OpenIdConnectConstants.Errors.InvalidGrant);
                    return null;
                }
            }

            await Options.Provider.ValidateTokenRequest(notification);

            var context = new GrantRefreshTokenNotification(Context, Options, notification.Request, ticket);

            if (notification.IsValidated) {
                await Options.Provider.GrantRefreshToken(context);
            }

            return ReturnOutcome(notification, context, context.Ticket, OpenIdConnectConstants.Errors.InvalidGrant);
        }

        private async Task<AuthenticationTicket> InvokeTokenEndpointCustomGrantAsync(ValidateTokenRequestNotification notification) {
            await Options.Provider.ValidateTokenRequest(notification);

            var context = new GrantCustomExtensionNotification(Context, Options, notification.Request);

            if (notification.IsValidated) {
                await Options.Provider.GrantCustomExtension(context);
            }

            return ReturnOutcome(notification, context, context.Ticket, OpenIdConnectConstants.Errors.UnsupportedGrantType);
        }

        private async Task InvokeValidationEndpointAsync() {
            OpenIdConnectMessage request;
            
            if (!string.Equals(Request.Method, "GET", StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(Request.Method, "POST", StringComparison.OrdinalIgnoreCase)) {
                await SendErrorPayloadAsync(new OpenIdConnectMessage {
                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = "A malformed validation request has been received: " +
                        "make sure to use either GET or POST."
                });

                return;
            }

            if (string.Equals(Request.Method, "GET", StringComparison.OrdinalIgnoreCase)) {
                request = new OpenIdConnectMessage(Request.Query) {
                    RequestType = OpenIdConnectRequestType.AuthenticationRequest
                };
            }

            else {
                // See http://openid.net/specs/openid-connect-core-1_0.html#FormSerialization
                if (string.IsNullOrEmpty(Request.ContentType)) {
                    await SendErrorPayloadAsync(new OpenIdConnectMessage {
                        Error = OpenIdConnectConstants.Errors.InvalidRequest,
                        ErrorDescription = "A malformed validation request has been received: " +
                            "the mandatory 'Content-Type' header was missing from the POST request."
                    });

                    return;
                }

                // May have media/type; charset=utf-8, allow partial match.
                if (!Request.ContentType.StartsWith("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase)) {
                    await SendErrorPayloadAsync(new OpenIdConnectMessage {
                        Error = OpenIdConnectConstants.Errors.InvalidRequest,
                        ErrorDescription = "A malformed validation request has been received: " +
                            "the 'Content-Type' header contained an unexcepted value. " +
                            "Make sure to use 'application/x-www-form-urlencoded'."
                    });

                    return;
                }

                request = new OpenIdConnectMessage(await Request.ReadFormAsync()) {
                    RequestType = OpenIdConnectRequestType.AuthenticationRequest
                };
            }

            AuthenticationTicket ticket;
            if (!string.IsNullOrEmpty(request.Token)) {
                ticket = await ReceiveAccessTokenAsync(request.Token, request);
            }

            else if (!string.IsNullOrEmpty(request.IdToken)) {
                ticket = await ReceiveIdentityTokenAsync(request.IdToken, request);
            }

            else if (!string.IsNullOrEmpty(request.GetRefreshToken())) {
                ticket = await ReceiveRefreshTokenAsync(request.GetRefreshToken(), request);
            }

            else {
                await SendErrorPayloadAsync(new OpenIdConnectMessage {
                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = "A malformed validation request has been received: " +
                        "either an identity token, an access token or a refresh token must be provided."
                });

                return;
            }

            if (ticket == null) {
                Logger.LogError("invalid token");

                await SendErrorPayloadAsync(new OpenIdConnectMessage {
                    Error = OpenIdConnectConstants.Errors.InvalidGrant,
                    ErrorDescription = "Invalid access token received"
                });

                return;
            }

            if (!ticket.Properties.ExpiresUtc.HasValue ||
                 ticket.Properties.ExpiresUtc < Options.SystemClock.UtcNow) {
                Logger.LogError("expired token");

                await SendErrorPayloadAsync(new OpenIdConnectMessage {
                    Error = OpenIdConnectConstants.Errors.InvalidGrant,
                    ErrorDescription = "Expired access token received"
                });

                return;
            }

            // Client applications and resource servers are strongly encouraged
            // to provide an audience parameter to mitigate confused deputy attacks.
            // See http://en.wikipedia.org/wiki/Confused_deputy_problem.
            var audiences = ticket.Properties.GetAudiences();
            if (audiences.Any() && !audiences.ContainsSet(request.GetAudiences())) {
                await SendErrorPayloadAsync(new OpenIdConnectMessage {
                    Error = OpenIdConnectConstants.Errors.InvalidGrant,
                    ErrorDescription = "Invalid access token received: " +
                        "the audience doesn't correspond to the registered value"
                });

                return;
            }

            var notification = new ValidationEndpointNotification(Context, Options, request, ticket);

            // Add the claims extracted from the access token.
            foreach (var claim in ticket.Principal.Claims) {
                notification.Claims.Add(claim);
            }

            await Options.Provider.ValidationEndpoint(notification);

            // Flow the changes made to the authentication ticket.
            ticket = notification.AuthenticationTicket;

            if (notification.HandledResponse) {
                return;
            }

            var payload = new JObject();

            payload.Add("audiences", JArray.FromObject(ticket.Properties.GetAudiences()));
            payload.Add("expires_in", ticket.Properties.ExpiresUtc.Value);

            payload.Add("claims", JArray.FromObject(
                from claim in notification.Claims
                select new { type = claim.Type, value = claim.Value }
            ));

            var responseNotification = new ValidationEndpointResponseNotification(Context, Options, payload);
            await Options.Provider.ValidationEndpointResponse(responseNotification);

            if (responseNotification.HandledResponse) {
                return;
            }

            using (var buffer = new MemoryStream())
            using (var writer = new JsonTextWriter(new StreamWriter(buffer))) {
                payload.WriteTo(writer);
                writer.Flush();

                Response.ContentLength = buffer.Length;
                Response.ContentType = "application/json;charset=UTF-8";

                Response.Headers.Set("Cache-Control", "no-cache");
                Response.Headers.Set("Pragma", "no-cache");
                Response.Headers.Set("Expires", "-1");

                buffer.Seek(offset: 0, loc: SeekOrigin.Begin);
                await buffer.CopyToAsync(Response.Body, 4096, Context.RequestAborted);
            }
        }

        private async Task<bool> InvokeLogoutEndpointAsync() {
            OpenIdConnectMessage request = null;

            // In principle, logout requests must be made via GET. Nevertheless,
            // POST requests are also allowed so that the inner application can display a logout form.
            // See https://openid.net/specs/openid-connect-session-1_0.html#RPLogout
            if (!string.Equals(Request.Method, "GET", StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(Request.Method, "POST", StringComparison.OrdinalIgnoreCase)) {
                return await SendErrorPageAsync(new OpenIdConnectMessage {
                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = "A malformed logout request has been received: " +
                        "make sure to use either GET or POST."
                });
            }

            if (string.Equals(Request.Method, "GET", StringComparison.OrdinalIgnoreCase)) {
                request = new OpenIdConnectMessage(Request.Query) {
                    RequestType = OpenIdConnectRequestType.LogoutRequest
                };
            }

            else {
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

                request = new OpenIdConnectMessage(await Request.ReadFormAsync()) {
                    RequestType = OpenIdConnectRequestType.LogoutRequest
                };
            }

            // Note: post_logout_redirect_uri is not a mandatory parameter.
            // See http://openid.net/specs/openid-connect-session-1_0.html#RPLogout
            if (!string.IsNullOrEmpty(request.PostLogoutRedirectUri)) {
                var clientNotification = new ValidateClientLogoutRedirectUriNotification(Context, Options, request);
                await Options.Provider.ValidateClientLogoutRedirectUri(clientNotification);

                if (!clientNotification.IsValidated) {
                    Logger.LogVerbose("Unable to validate client information");

                    return await SendErrorPageAsync(new OpenIdConnectMessage {
                        Error = clientNotification.Error,
                        ErrorDescription = clientNotification.ErrorDescription,
                        ErrorUri = clientNotification.ErrorUri
                    });
                }
            }

            // Update the logout request in the ASP.NET context.
            Context.SetOpenIdConnectRequest(request);

            var notification = new LogoutEndpointNotification(Context, Options, request);
            await Options.Provider.LogoutEndpoint(notification);

            // Update the logout request in the ASP.NET context.
            Context.SetOpenIdConnectRequest(request);

            if (notification.HandledResponse) {
                return true;
            }

            return false;
        }

        private async Task<string> CreateAuthorizationCodeAsync(
            ClaimsPrincipal principal, AuthenticationProperties properties,
            OpenIdConnectMessage request, OpenIdConnectMessage response) {
            try {
                // properties.IssuedUtc and properties.ExpiresUtc
                // should always be preferred when explicitly set.
                if (properties.IssuedUtc == null) {
                    properties.IssuedUtc = Options.SystemClock.UtcNow;
                }

                if (properties.ExpiresUtc == null) {
                    properties.ExpiresUtc = properties.IssuedUtc + Options.AuthorizationCodeLifetime;
                }

                // Claims in authorization codes are never filtered as they are supposed to be opaque:
                // CreateAccessTokenAsync and CreateIdentityTokenAsync are responsible of ensuring
                // that subsequent access and identity tokens are correctly filtered.
                var ticket = new AuthenticationTicket(principal, properties, Options.AuthenticationScheme);

                var notification = new CreateAuthorizationCodeNotification(Context, Options, request, response, ticket) {
                    DataFormat = Options.AuthorizationCodeFormat
                };

                await Options.Provider.CreateAuthorizationCode(notification);

                // Allow the application to change the authentication
                // ticket from the CreateAuthorizationCode notification.
                ticket = notification.AuthenticationTicket;
                ticket.Properties.CopyTo(properties);

                if (notification.HandledResponse) {
                    return notification.AuthorizationCode;
                }

                else if (notification.Skipped) {
                    return null;
                }

                var key = GenerateKey(256 / 8);

                using (var stream = new MemoryStream())
                using (var writter = new StreamWriter(stream)) {
                    writter.Write(await notification.SerializeTicketAsync());
                    writter.Flush();

                    await Options.Cache.SetAsync(key, options => {
                        options.AbsoluteExpiration = ticket.Properties.ExpiresUtc;

                        return stream.ToArray();
                    });
                }

                return key;
            }

            catch (Exception exception) {
                Logger.LogWarning("An exception occured when serializing an authorization code.", exception);

                return null;
            }
        }

        private async Task<string> CreateAccessTokenAsync(
            ClaimsPrincipal principal, AuthenticationProperties properties,
            OpenIdConnectMessage request, OpenIdConnectMessage response) {
            try {
                // properties.IssuedUtc and properties.ExpiresUtc
                // should always be preferred when explicitly set.
                if (properties.IssuedUtc == null) {
                    properties.IssuedUtc = Options.SystemClock.UtcNow;
                }

                if (properties.ExpiresUtc == null) {
                    properties.ExpiresUtc = properties.IssuedUtc + Options.AccessTokenLifetime;
                }

                // Create a new principal containing only the filtered claims.
                // Actors identities are also filtered (delegation scenarios).
                principal = principal.Clone(claim => {
                    // ClaimTypes.NameIdentifier and JwtRegisteredClaimNames.Sub are never excluded.
                    if (string.Equals(claim.Type, ClaimTypes.NameIdentifier, StringComparison.Ordinal) ||
                        string.Equals(claim.Type, JwtRegisteredClaimNames.Sub, StringComparison.Ordinal)) {
                        return true;
                    }

                    // Claims whose destination is not explicitly referenced or
                    // doesn't contain "token" are not included in the access token.
                    return claim.HasDestination(OpenIdConnectConstants.ResponseTypes.Token);
                });

                var identity = (ClaimsIdentity) principal.Identity;

                var resources = request.GetResources();
                if (!resources.Any()) {
                    // When no explicit resource parameter has been included in the token request,
                    // the optional resource received during the authorization request is used instead
                    // to help reducing cases where access tokens are issued for unknown resources.
                    resources = properties.GetResources();
                }

                // Note: when used as an access token, a JWT token doesn't have to expose a "sub" claim
                // but the name identifier claim is used as a substitute when it has been explicitly added.
                // See https://tools.ietf.org/html/rfc7519#section-4.1.2
                var subject = identity.FindFirst(JwtRegisteredClaimNames.Sub);
                if (subject == null) {
                    var identifier = identity.FindFirst(ClaimTypes.NameIdentifier);
                    if (identifier != null) {
                        identity.AddClaim(JwtRegisteredClaimNames.Sub, identifier.Value);
                    }
                }

                // Create a new ticket containing the updated properties and the filtered principal.
                var ticket = new AuthenticationTicket(principal, properties, Options.AuthenticationScheme);

                var notification = new CreateAccessTokenNotification(Context, Options, request, response, ticket) {
                    DataFormat = Options.AccessTokenFormat,
                    Issuer = Context.GetIssuer(Options),
                    SecurityTokenHandler = Options.AccessTokenHandler,
                    SignatureProvider = Options.SignatureProvider,
                    SigningCredentials = Options.SigningCredentials
                };

                foreach (var audience in resources) {
                    notification.Audiences.Add(audience);
                }

                await Options.Provider.CreateAccessToken(notification);

                // Allow the application to change the authentication
                // ticket from the CreateAccessTokenAsync notification.
                ticket = notification.AuthenticationTicket;
                ticket.Properties.CopyTo(properties);

                if (notification.HandledResponse) {
                    return notification.AccessToken;
                }

                else if (notification.Skipped) {
                    return null;
                }

                return await notification.SerializeTicketAsync();
            }

            catch (Exception exception) {
                Logger.LogWarning("An exception occured when serializing an access token.", exception);

                return null;
            }
        }

        private async Task<string> CreateIdentityTokenAsync(
            ClaimsPrincipal principal, AuthenticationProperties properties,
            OpenIdConnectMessage request, OpenIdConnectMessage response) {
            try {
                // properties.IssuedUtc and properties.ExpiresUtc
                // should always be preferred when explicitly set.
                if (properties.IssuedUtc == null) {
                    properties.IssuedUtc = Options.SystemClock.UtcNow;
                }

                if (properties.ExpiresUtc == null) {
                    properties.ExpiresUtc = properties.IssuedUtc + Options.IdentityTokenLifetime;
                }

                // Replace the principal by a new one containing only the filtered claims.
                // Actors identities are also filtered (delegation scenarios).
                principal = principal.Clone(claim => {
                    // ClaimTypes.NameIdentifier and JwtRegisteredClaimNames.Sub are never excluded.
                    if (string.Equals(claim.Type, ClaimTypes.NameIdentifier, StringComparison.Ordinal) ||
                        string.Equals(claim.Type, JwtRegisteredClaimNames.Sub, StringComparison.Ordinal)) {
                        return true;
                    }

                    // Claims whose destination is not explicitly referenced or
                    // doesn't contain "id_token" are not included in the identity token.
                    return claim.HasDestination(OpenIdConnectConstants.ResponseTypes.IdToken);
                });

                var identity = (ClaimsIdentity) principal.Identity;

                identity.AddClaim(JwtRegisteredClaimNames.Iat,
                    EpochTime.GetIntDate(properties.IssuedUtc.Value.UtcDateTime).ToString());

                // Only add c_hash and at_hash if signing credentials have been explictly provided.
                // Note: JwtHeader's constructor will automatically use the "none" algorithm in this case.
                if (Options.SigningCredentials != null) {
                    if (!string.IsNullOrEmpty(response.Code)) {
                        // Create the c_hash using the authorization code returned by CreateAuthorizationCodeAsync.
                        var hash = GenerateHash(response.Code, Options.SigningCredentials.DigestAlgorithm);

                        identity.AddClaim(JwtRegisteredClaimNames.CHash, hash);
                    }

                    if (!string.IsNullOrEmpty(response.AccessToken)) {
                        // Create the at_hash using the access token returned by CreateAccessTokenAsync.
                        var hash = GenerateHash(response.AccessToken, Options.SigningCredentials.DigestAlgorithm);

                        identity.AddClaim("at_hash", hash);
                    }
                }

                if (!string.IsNullOrEmpty(request.Nonce)) {
                    identity.AddClaim(JwtRegisteredClaimNames.Nonce, request.Nonce);
                }

                // While the 'sub' claim is declared mandatory by the OIDC specs,
                // it is not always issued as-is by the authorization servers.
                // When missing, the name identifier claim is used as a substitute.
                // See http://openid.net/specs/openid-connect-core-1_0.html#IDToken
                var subject = principal.FindFirst(JwtRegisteredClaimNames.Sub);
                if (subject == null) {
                    var identifier = principal.FindFirst(ClaimTypes.NameIdentifier);
                    if (identifier == null) {
                        throw new InvalidOperationException(
                            "A unique identifier cannot be found to generate a 'sub' claim. " +
                            "Make sure to either add a 'sub' or a 'ClaimTypes.NameIdentifier' claim " +
                            "in the returned ClaimsIdentity before calling SignIn.");
                    }

                    identity.AddClaim(JwtRegisteredClaimNames.Sub, identifier.Value);
                }

                // Create a new ticket containing the updated properties and the filtered principal.
                var ticket = new AuthenticationTicket(principal, properties, Options.AuthenticationScheme);

                var notification = new CreateIdentityTokenNotification(Context, Options, request, response, ticket) {
                    Audiences = { request.ClientId },
                    Issuer = Context.GetIssuer(Options),
                    SecurityTokenHandler = Options.IdentityTokenHandler,
                    SignatureProvider = Options.SignatureProvider,
                    SigningCredentials = Options.SigningCredentials
                };

                await Options.Provider.CreateIdentityToken(notification);

                // Allow the application to change the authentication
                // ticket from the CreateIdentityTokenAsync notification.
                ticket = notification.AuthenticationTicket;
                ticket.Properties.CopyTo(properties);

                if (notification.HandledResponse) {
                    return notification.IdentityToken;
                }

                else if (notification.Skipped) {
                    return null;
                }

                return await notification.SerializeTicketAsync();
            }

            catch (Exception exception) {
                Logger.LogWarning("An exception occured when serializing an identity token.", exception);

                return null;
            }
        }

        private async Task<string> CreateRefreshTokenAsync(
            ClaimsPrincipal principal, AuthenticationProperties properties,
            OpenIdConnectMessage request, OpenIdConnectMessage response) {
            try {
                // properties.IssuedUtc and properties.ExpiresUtc
                // should always be preferred when explicitly set.
                if (properties.IssuedUtc == null) {
                    properties.IssuedUtc = Options.SystemClock.UtcNow;
                }

                if (properties.ExpiresUtc == null) {
                    properties.ExpiresUtc = properties.IssuedUtc + Options.RefreshTokenLifetime;
                }

                // Claims in refresh tokens are never filtered as they are supposed to be opaque:
                // CreateAccessTokenAsync and CreateIdentityTokenAsync are responsible of ensuring
                // that subsequent access and identity tokens are correctly filtered.
                var ticket = new AuthenticationTicket(principal, properties, Options.AuthenticationScheme);

                var notification = new CreateRefreshTokenNotification(Context, Options, request, response, ticket) {
                    DataFormat = Options.RefreshTokenFormat
                };

                await Options.Provider.CreateRefreshToken(notification);

                // Allow the application to change the authentication
                // ticket from the CreateRefreshTokenAsync notification.
                ticket = notification.AuthenticationTicket;
                ticket.Properties.CopyTo(properties);

                if (notification.HandledResponse) {
                    return notification.RefreshToken;
                }

                else if (notification.Skipped) {
                    return null;
                }

                return await notification.SerializeTicketAsync();
            }

            catch (Exception exception) {
                Logger.LogWarning("An exception occured when serializing a refresh token.", exception);

                return null;
            }
        }

        private async Task<AuthenticationTicket> ReceiveAuthorizationCodeAsync(string code, OpenIdConnectMessage request) {
            try {
                var notification = new ReceiveAuthorizationCodeNotification(Context, Options, request, code) {
                    DataFormat = Options.AuthorizationCodeFormat
                };

                await Options.Provider.ReceiveAuthorizationCode(notification);

                // Directly return the authentication ticket if one
                // has been provided by ReceiveAuthorizationCode.
                if (notification.HandledResponse) {
                    return notification.AuthenticationTicket;
                }

                else if (notification.Skipped) {
                    return null;
                }

                var buffer = await Options.Cache.GetAsync(code);
                if (buffer == null) {
                    return null;
                }

                using (var stream = new MemoryStream(buffer))
                using (var reader = new StreamReader(stream)) {
                    // Because authorization codes are guaranteed to be unique, make sure
                    // to remove the current code from the global store before using it.
                    await Options.Cache.RemoveAsync(code);

                    return await notification.DeserializeTicketAsync(await reader.ReadToEndAsync());
                }
            }

            catch (Exception exception) {
                Logger.LogWarning("An exception occured when deserializing an authorization code.", exception);

                return null;
            }
        }

        private async Task<AuthenticationTicket> ReceiveAccessTokenAsync(string token, OpenIdConnectMessage request) {
            try {
                var notification = new ReceiveAccessTokenNotification(Context, Options, request, token) {
                    DataFormat = Options.AccessTokenFormat,
                    Issuer = Context.GetIssuer(Options),
                    SecurityTokenHandler = Options.AccessTokenHandler,
                    SignatureProvider = Options.SignatureProvider,
                    SigningCredentials = Options.SigningCredentials
                };

                await Options.Provider.ReceiveAccessToken(notification);

                // Directly return the authentication ticket if one
                // has been provided by ReceiveAccessToken.
                if (notification.HandledResponse) {
                    return notification.AuthenticationTicket;
                }

                else if (notification.Skipped) {
                    return null;
                }

                return await notification.DeserializeTicketAsync(token);
            }

            catch (Exception exception) {
                Logger.LogWarning("An exception occured when deserializing an access token.", exception);

                return null;
            }
        }

        private async Task<AuthenticationTicket> ReceiveIdentityTokenAsync(string token, OpenIdConnectMessage request) {
            try {
                var notification = new ReceiveIdentityTokenNotification(Context, Options, request, token) {
                    Issuer = Context.GetIssuer(Options),
                    SecurityTokenHandler = Options.IdentityTokenHandler,
                    SignatureProvider = Options.SignatureProvider,
                    SigningCredentials = Options.SigningCredentials
                };

                await Options.Provider.ReceiveIdentityToken(notification);

                // Directly return the authentication ticket if one
                // has been provided by ReceiveIdentityToken.
                if (notification.HandledResponse) {
                    return notification.AuthenticationTicket;
                }

                else if (notification.Skipped) {
                    return null;
                }

                return await notification.DeserializeTicketAsync(token);
            }

            catch (Exception exception) {
                Logger.LogWarning("An exception occured when deserializing an identity token.", exception);

                return null;
            }
        }

        private async Task<AuthenticationTicket> ReceiveRefreshTokenAsync(string token, OpenIdConnectMessage request) {
            try {
                var notification = new ReceiveRefreshTokenNotification(Context, Options, request, token) {
                    DataFormat = Options.RefreshTokenFormat
                };

                await Options.Provider.ReceiveRefreshToken(notification);

                // Directly return the authentication ticket if one
                // has been provided by ReceiveRefreshToken.
                if (notification.HandledResponse) {
                    return notification.AuthenticationTicket;
                }

                else if (notification.Skipped) {
                    return null;
                }

                return await notification.DeserializeTicketAsync(token);
            }

            catch (Exception exception) {
                Logger.LogWarning("An exception occured when deserializing a refresh token.", exception);

                return null;
            }
        }

        private static AuthenticationTicket ReturnOutcome(
            ValidateTokenRequestNotification validatingContext,
            BaseValidatingNotification<OpenIdConnectServerOptions> grantContext,
            AuthenticationTicket ticket,
            string defaultError) {
            if (!validatingContext.IsValidated) {
                return null;
            }

            if (!grantContext.IsValidated) {
                if (grantContext.HasError) {
                    validatingContext.SetError(
                        grantContext.Error,
                        grantContext.ErrorDescription,
                        grantContext.ErrorUri);
                }
                else {
                    validatingContext.SetError(defaultError);
                }
                return null;
            }

            if (ticket == null) {
                validatingContext.SetError(defaultError);
                return null;
            }

            return ticket;
        }

        private async Task<bool> SendErrorRedirectAsync(OpenIdConnectMessage request, OpenIdConnectMessage response) {
            // Remove the authorization request from the ASP.NET context to inform
            // TeardownCoreAsync that there's nothing more to handle.
            Context.SetOpenIdConnectRequest(request: null);

            // Use a generic error if none has been explicitly provided.
            if (string.IsNullOrEmpty(response.Error)) {
                response.Error = OpenIdConnectConstants.Errors.InvalidRequest;
            }

            // Directly display an error page if redirect_uri cannot be used.
            if (string.IsNullOrEmpty(response.RedirectUri)) {
                return await SendErrorPageAsync(response);
            }

            // Try redirecting the user agent to the client
            // application or display a default error page.
            if (!await ApplyAuthorizationResponseAsync(request, response)) {
                return await SendErrorPageAsync(response);
            }

            // Stop processing the request.
            return true;
        }

        private async Task<bool> SendErrorPageAsync(OpenIdConnectMessage response) {
            // Use a generic error if none has been explicitly provided.
            if (string.IsNullOrEmpty(response.Error)) {
                response.Error = OpenIdConnectConstants.Errors.InvalidRequest;
            }

            if (Options.ApplicationCanDisplayErrors) {
                Context.SetOpenIdConnectResponse(response);

                // Request is not handled - pass through to application for rendering.
                return false;
            }

            using (var buffer = new MemoryStream())
            using (var writer = new StreamWriter(buffer)) {
                foreach (var parameter in response.Parameters) {
                    writer.WriteLine("{0}: {1}", parameter.Key, parameter.Value);
                }

                writer.Flush();

                Response.StatusCode = 400;
                Response.ContentLength = buffer.Length;
                Response.ContentType = "text/plain;charset=UTF-8";

                Response.Headers.Set("Cache-Control", "no-cache");
                Response.Headers.Set("Pragma", "no-cache");
                Response.Headers.Set("Expires", "-1");

                buffer.Seek(offset: 0, loc: SeekOrigin.Begin);
                await buffer.CopyToAsync(Response.Body, 4096, Context.RequestAborted);

                return true;
            }
        }

        private async Task SendErrorPayloadAsync(OpenIdConnectMessage response) {
            using (var buffer = new MemoryStream())
            using (var writer = new JsonTextWriter(new StreamWriter(buffer))) {
                var payload = new JObject();

                payload.Add(OpenIdConnectConstants.Parameters.Error, response.Error);

                if (!string.IsNullOrEmpty(response.ErrorDescription)) {
                    payload.Add(OpenIdConnectConstants.Parameters.ErrorDescription, response.ErrorDescription);
                }

                if (!string.IsNullOrEmpty(response.ErrorUri)) {
                    payload.Add(OpenIdConnectConstants.Parameters.ErrorUri, response.ErrorUri);
                }

                payload.WriteTo(writer);
                writer.Flush();

                Response.StatusCode = 400;
                Response.ContentLength = buffer.Length;
                Response.ContentType = "application/json;charset=UTF-8";

                Response.Headers.Set("Cache-Control", "no-cache");
                Response.Headers.Set("Pragma", "no-cache");
                Response.Headers.Set("Expires", "-1");

                buffer.Seek(offset: 0, loc: SeekOrigin.Begin);
                await buffer.CopyToAsync(Response.Body, 4096, Context.RequestAborted);
            }
        }

        private static HashAlgorithm GetHashAlgorithm(string algorithm) {
            if (string.IsNullOrEmpty(algorithm)) {
                throw new ArgumentNullException(nameof(algorithm));
            }

            switch (algorithm) {
                case SecurityAlgorithms.Sha1Digest:
                    return SHA1.Create();

                case SecurityAlgorithms.Sha256Digest:
                    return SHA256.Create();

                case SecurityAlgorithms.Sha512Digest:
                    return SHA512.Create();

                default:
                    throw new ArgumentOutOfRangeException(nameof(algorithm));
            }
        }

        private static string GenerateHash(string value, string algorithm = null) {
            using (var hashAlgorithm = GetHashAlgorithm(algorithm ?? SecurityAlgorithms.Sha256Digest)) {
                byte[] hashBytes = hashAlgorithm.ComputeHash(Encoding.UTF8.GetBytes(value));

                var hashString = Convert.ToBase64String(hashBytes, 0, hashBytes.Length / 2);
                hashString = hashString.Split('=')[0]; // Remove any trailing padding
                hashString = hashString.Replace('+', '-'); // 62nd char of encoding
                return hashString.Replace('/', '_'); // 63rd char of encoding
            }
        }

        private string GenerateKey(int length) {
            var bytes = new byte[length];
            Options.RandomNumberGenerator.GetBytes(bytes);
            return Convert.ToBase64String(bytes);
        }

        private class Appender {
            private readonly char _delimiter;
            private readonly StringBuilder _sb;
            private bool _hasDelimiter;

            public Appender(string value, char delimiter) {
                _sb = new StringBuilder(value);
                _delimiter = delimiter;
                _hasDelimiter = value.IndexOf(delimiter) != -1;
            }

            public Appender Append(string name, string value) {
                _sb.Append(_hasDelimiter ? '&' : _delimiter)
                   .Append(Uri.EscapeDataString(name))
                   .Append('=')
                   .Append(Uri.EscapeDataString(value));
                _hasDelimiter = true;
                return this;
            }

            public override string ToString() {
                return _sb.ToString();
            }
        }
    }
}