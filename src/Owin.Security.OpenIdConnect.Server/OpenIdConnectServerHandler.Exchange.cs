/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Protocols;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using Newtonsoft.Json.Linq;
using Owin.Security.OpenIdConnect.Extensions;

namespace Owin.Security.OpenIdConnect.Server {
    internal partial class OpenIdConnectServerHandler : AuthenticationHandler<OpenIdConnectServerOptions> {
        private async Task<bool> InvokeTokenEndpointAsync() {
            if (!string.Equals(Request.Method, "POST", StringComparison.OrdinalIgnoreCase)) {
                Options.Logger.LogError("The token request was rejected because an invalid " +
                                        "HTTP method was received: {Method}.", Request.Method);

                return await SendTokenResponseAsync(null, new OpenIdConnectMessage {
                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = "A malformed token request has been received: make sure to use POST."
                });
            }

            // See http://openid.net/specs/openid-connect-core-1_0.html#FormSerialization
            if (string.IsNullOrEmpty(Request.ContentType)) {
                Options.Logger.LogError("The token request was rejected because the " +
                                        "mandatory 'Content-Type' header was missing.");

                return await SendTokenResponseAsync(null, new OpenIdConnectMessage {
                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = "A malformed token request has been received: " +
                        "the mandatory 'Content-Type' header was missing from the POST request."
                });
            }

            // May have media/type; charset=utf-8, allow partial match.
            if (!Request.ContentType.StartsWith("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase)) {
                Options.Logger.LogError("The token request was rejected because an invalid 'Content-Type' " +
                                        "header was received: {ContentType}.", Request.ContentType);

                return await SendTokenResponseAsync(null, new OpenIdConnectMessage {
                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = "A malformed token request has been received: " +
                        "the 'Content-Type' header contained an unexcepted value. " +
                        "Make sure to use 'application/x-www-form-urlencoded'."
                });
            }

            var request = new OpenIdConnectMessage(await Request.ReadFormAsync()) {
                RequestType = OpenIdConnectRequestType.TokenRequest
            };

            // Store the token request in the OWIN context.
            Context.SetOpenIdConnectRequest(request);

            // Reject token requests missing the mandatory grant_type parameter.
            if (string.IsNullOrEmpty(request.GrantType)) {
                Options.Logger.LogError("The token request was rejected because the grant type was missing.");

                return await SendTokenResponseAsync(request, new OpenIdConnectMessage {
                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = "The mandatory 'grant_type' parameter was missing.",
                });
            }

            // Reject grant_type=authorization_code requests missing the authorization code.
            // See https://tools.ietf.org/html/rfc6749#section-4.1.3
            else if (request.IsAuthorizationCodeGrantType() && string.IsNullOrEmpty(request.Code)) {
                Options.Logger.LogError("The token request was rejected because the authorization code was missing.");

                return await SendTokenResponseAsync(request, new OpenIdConnectMessage {
                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = "The mandatory 'code' parameter was missing."
                });
            }

            // Reject grant_type=refresh_token requests missing the refresh token.
            // See https://tools.ietf.org/html/rfc6749#section-6
            else if (request.IsRefreshTokenGrantType() && string.IsNullOrEmpty(request.GetRefreshToken())) {
                Options.Logger.LogError("The token request was rejected because the refresh token was missing.");

                return await SendTokenResponseAsync(request, new OpenIdConnectMessage {
                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = "The mandatory 'refresh_token' parameter was missing."
                });
            }

            // Reject grant_type=password requests missing username or password.
            // See https://tools.ietf.org/html/rfc6749#section-4.3.2
            else if (request.IsPasswordGrantType() && (string.IsNullOrEmpty(request.Username) ||
                                                       string.IsNullOrEmpty(request.Password))) {
                Options.Logger.LogError("The token request was rejected because the resource owner credentials were missing.");

                return await SendTokenResponseAsync(request, new OpenIdConnectMessage {
                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = "The mandatory 'username' and/or 'password' parameters " +
                                       "was/were missing from the request message."
                });
            }

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

            var context = new ValidateTokenRequestContext(Context, Options, request);
            await Options.Provider.ValidateTokenRequest(context);

            if (context.IsRejected) {
                Options.Logger.LogInformation("The token request was rejected by application code.");

                return await SendTokenResponseAsync(request, new OpenIdConnectMessage {
                    Error = context.Error ?? OpenIdConnectConstants.Errors.InvalidClient,
                    ErrorDescription = context.ErrorDescription,
                    ErrorUri = context.ErrorUri
                });
            }

            // Reject grant_type=client_credentials requests if validation was skipped.
            else if (context.IsSkipped && request.IsClientCredentialsGrantType()) {
                Options.Logger.LogError("The token request must be fully validated to use the client_credentials grant type.");

                return await SendTokenResponseAsync(request, new OpenIdConnectMessage {
                    Error = OpenIdConnectConstants.Errors.InvalidGrant,
                    ErrorDescription = "Client authentication is required when using client_credentials."
                });
            }

            // Ensure that the client_id has been set from the ValidateTokenRequest event.
            else if (context.IsValidated && string.IsNullOrEmpty(request.ClientId)) {
                Options.Logger.LogError("The token request was validated but the client_id was not set.");

                return await SendTokenResponseAsync(request, new OpenIdConnectMessage {
                    Error = OpenIdConnectConstants.Errors.ServerError,
                    ErrorDescription = "An internal server error occurred."
                });
            }

            AuthenticationTicket ticket = null;

            // See http://tools.ietf.org/html/rfc6749#section-4.1
            // and http://tools.ietf.org/html/rfc6749#section-4.1.3 (authorization code grant).
            // See http://tools.ietf.org/html/rfc6749#section-6 (refresh token grant).
            if (request.IsAuthorizationCodeGrantType() || request.IsRefreshTokenGrantType()) {
                ticket = request.IsAuthorizationCodeGrantType() ?
                    await DeserializeAuthorizationCodeAsync(request.Code, request) :
                    await DeserializeRefreshTokenAsync(request.GetRefreshToken(), request);

                if (ticket == null) {
                    Options.Logger.LogError("The token request was rejected because the " +
                                            "authorization code or the refresh token was invalid.");

                    return await SendTokenResponseAsync(request, new OpenIdConnectMessage {
                        Error = OpenIdConnectConstants.Errors.InvalidGrant,
                        ErrorDescription = "Invalid ticket"
                    });
                }

                if (!ticket.Properties.ExpiresUtc.HasValue ||
                     ticket.Properties.ExpiresUtc < Options.SystemClock.UtcNow) {
                    Options.Logger.LogError("The token request was rejected because the " +
                                            "authorization code or the refresh token was expired.");

                    return await SendTokenResponseAsync(request, new OpenIdConnectMessage {
                        Error = OpenIdConnectConstants.Errors.InvalidGrant,
                        ErrorDescription = "Expired ticket"
                    });
                }

                // If the client was fully authenticated when retrieving its refresh token,
                // the current request must be rejected if client authentication was not enforced.
                if (request.IsRefreshTokenGrantType() && !context.IsValidated && ticket.IsConfidential()) {
                    Options.Logger.LogError("The token request was rejected because client authentication " +
                                            "was required to use the confidential refresh token.");

                    return await SendTokenResponseAsync(request, new OpenIdConnectMessage {
                        Error = OpenIdConnectConstants.Errors.InvalidGrant,
                        ErrorDescription = "Client authentication is required to use this ticket"
                    });
                }

                // Note: presenters may be empty during a grant_type=refresh_token request if the refresh token
                // was issued to a public client but cannot be null for an authorization code grant request.
                var presenters = ticket.GetPresenters();
                if (request.IsAuthorizationCodeGrantType() && !presenters.Any()) {
                    Options.Logger.LogError("The token request was rejected because the authorization " +
                                            "code didn't contain any valid presenter.");

                    return await SendTokenResponseAsync(request, new OpenIdConnectMessage {
                        Error = OpenIdConnectConstants.Errors.ServerError,
                        ErrorDescription = "An internal server error occurred."
                    });
                }

                // At this stage, client_id cannot be null for grant_type=authorization_code requests,
                // as it must either be set in the ValidateTokenRequest notification
                // by the developer or manually flowed by non-confidential client applications.
                // See https://tools.ietf.org/html/rfc6749#section-4.1.3
                if (request.IsAuthorizationCodeGrantType() && string.IsNullOrEmpty(request.ClientId)) {
                    Options.Logger.LogError("The token request was rejected because the mandatory 'client_id' was missing.");

                    return await SendTokenResponseAsync(request, new OpenIdConnectMessage {
                        Error = OpenIdConnectConstants.Errors.InvalidRequest,
                        ErrorDescription = "client_id was missing from the token request"
                    });
                }

                // Ensure the authorization code/refresh token was issued to the client application making the token request.
                // Note: when using the refresh token grant, client_id is optional but must validated if present.
                // As a consequence, this check doesn't depend on the actual status of client authentication.
                // See https://tools.ietf.org/html/rfc6749#section-6
                // and http://openid.net/specs/openid-connect-core-1_0.html#RefreshingAccessToken
                if (!string.IsNullOrEmpty(request.ClientId) && presenters.Any() &&
                    !presenters.Contains(request.ClientId, StringComparer.Ordinal)) {
                    Options.Logger.LogError("The token request was rejected because the authorization " +
                                            "code was issued to a different client application.");

                    return await SendTokenResponseAsync(request, new OpenIdConnectMessage {
                        Error = OpenIdConnectConstants.Errors.InvalidGrant,
                        ErrorDescription = "Ticket does not contain matching client_id"
                    });
                }

                // Validate the redirect_uri flowed by the client application during this token request.
                // Note: for pure OAuth2 requests, redirect_uri is only mandatory if the authorization request
                // contained an explicit redirect_uri. OpenID Connect requests MUST include a redirect_uri
                // but the specifications allow proceeding the token request without returning an error
                // if the authorization request didn't contain an explicit redirect_uri.
                // See https://tools.ietf.org/html/rfc6749#section-4.1.3
                // and http://openid.net/specs/openid-connect-core-1_0.html#TokenRequestValidation
                var address = ticket.GetProperty(OpenIdConnectConstants.Properties.RedirectUri);
                if (request.IsAuthorizationCodeGrantType() && !string.IsNullOrEmpty(address)) {
                    ticket.Properties.Dictionary.Remove(OpenIdConnectConstants.Properties.RedirectUri);

                    if (string.IsNullOrEmpty(request.RedirectUri)) {
                        Options.Logger.LogError("The token request was rejected because the mandatory 'redirect_uri' " +
                                                "parameter was missing from the grant_type=authorization_code request.");

                        return await SendTokenResponseAsync(request, new OpenIdConnectMessage {
                            Error = OpenIdConnectConstants.Errors.InvalidRequest,
                            ErrorDescription = "redirect_uri was missing from the token request"
                        });
                    }

                    else if (!string.Equals(address, request.RedirectUri, StringComparison.Ordinal)) {
                        Options.Logger.LogError("The token request was rejected because the 'redirect_uri' " +
                                                "parameter didn't correspond to the expected value.");

                        return await SendTokenResponseAsync(request, new OpenIdConnectMessage {
                            Error = OpenIdConnectConstants.Errors.InvalidGrant,
                            ErrorDescription = "Authorization code does not contain matching redirect_uri"
                        });
                    }
                }

                if (request.IsRefreshTokenGrantType() && !string.IsNullOrEmpty(request.Resource)) {
                    // When an explicit resource parameter has been included in the token request
                    // but was missing from the initial request, the request MUST be rejected.
                    var resources = ticket.GetResources();
                    if (!resources.Any()) {
                        Options.Logger.LogError("The token request was rejected because the 'resource' parameter was not allowed.");

                        return await SendTokenResponseAsync(request, new OpenIdConnectMessage {
                            Error = OpenIdConnectConstants.Errors.InvalidGrant,
                            ErrorDescription = "Token request cannot contain a resource parameter" +
                                               "if the authorization request didn't contain one"
                        });
                    }

                    // When an explicit resource parameter has been included in the token request,
                    // the authorization server MUST ensure that it doesn't contain resources
                    // that were not allowed during the initial authorization/token request.
                    else if (!new HashSet<string>(resources).IsSupersetOf(request.GetResources())) {
                        Options.Logger.LogError("The token request was rejected because the 'resource' parameter was not valid.");

                        return await SendTokenResponseAsync(request, new OpenIdConnectMessage {
                            Error = OpenIdConnectConstants.Errors.InvalidGrant,
                            ErrorDescription = "Token request doesn't contain a valid resource parameter"
                        });
                    }
                }

                if (request.IsRefreshTokenGrantType() && !string.IsNullOrEmpty(request.Scope)) {
                    // When an explicit scope parameter has been included in the token request
                    // but was missing from the initial request, the request MUST be rejected.
                    // See http://tools.ietf.org/html/rfc6749#section-6
                    var scopes = ticket.GetScopes();
                    if (!scopes.Any()) {
                        Options.Logger.LogError("The token request was rejected because the 'scope' parameter was not allowed.");

                        return await SendTokenResponseAsync(request, new OpenIdConnectMessage {
                            Error = OpenIdConnectConstants.Errors.InvalidGrant,
                            ErrorDescription = "Token request cannot contain a scope parameter" +
                                               "if the authorization request didn't contain one"
                        });
                    }

                    // When an explicit scope parameter has been included in the token request,
                    // the authorization server MUST ensure that it doesn't contain scopes
                    // that were not allowed during the initial authorization/token request.
                    // See https://tools.ietf.org/html/rfc6749#section-6
                    else if (!new HashSet<string>(scopes).IsSupersetOf(request.GetScopes())) {
                        Options.Logger.LogError("The token request was rejected because the 'scope' parameter was not valid.");

                        return await SendTokenResponseAsync(request, new OpenIdConnectMessage {
                            Error = OpenIdConnectConstants.Errors.InvalidGrant,
                            ErrorDescription = "Token request doesn't contain a valid scope parameter"
                        });
                    }
                }

                if (request.IsAuthorizationCodeGrantType()) {
                    // Note: the authentication ticket is copied to avoid modifying the properties of the authorization code.
                    var grant = new GrantAuthorizationCodeContext(Context, Options, request, ticket.Copy());
                    await Options.Provider.GrantAuthorizationCode(grant);

                    if (!grant.IsValidated) {
                        // Note: use invalid_grant as the default error if none has been explicitly provided.
                        return await SendTokenResponseAsync(request, new OpenIdConnectMessage {
                            Error = grant.Error ?? OpenIdConnectConstants.Errors.InvalidGrant,
                            ErrorDescription = grant.ErrorDescription,
                            ErrorUri = grant.ErrorUri
                        });
                    }

                    // By default, when using the authorization code grant, the authentication ticket extracted from the
                    // authorization code is used as-is. To avoid aligning the expiration date of the generated tokens
                    // with the lifetime of the authorization code, the ticket properties are automatically reset to null.
                    if (grant.Ticket.Properties.IssuedUtc == ticket.Properties.IssuedUtc) {
                        grant.Ticket.Properties.IssuedUtc = null;
                    }

                    if (grant.Ticket.Properties.ExpiresUtc == ticket.Properties.ExpiresUtc) {
                        grant.Ticket.Properties.ExpiresUtc = null;
                    }

                    ticket = grant.Ticket;
                }

                else {
                    // Note: the authentication ticket is copied to avoid modifying the properties of the refresh token.
                    var grant = new GrantRefreshTokenContext(Context, Options, request, ticket.Copy());
                    await Options.Provider.GrantRefreshToken(grant);

                    if (!grant.IsValidated) {
                        // Note: use invalid_grant as the default error if none has been explicitly provided.
                        return await SendTokenResponseAsync(request, new OpenIdConnectMessage {
                            Error = grant.Error ?? OpenIdConnectConstants.Errors.InvalidGrant,
                            ErrorDescription = grant.ErrorDescription,
                            ErrorUri = grant.ErrorUri
                        });
                    }

                    // By default, when using the refresh token grant, the authentication ticket extracted from the
                    // refresh token is used as-is. To avoid aligning the expiration date of the generated tokens
                    // with the lifetime of the refresh token, the ticket properties are automatically reset to null.
                    if (grant.Ticket.Properties.IssuedUtc == ticket.Properties.IssuedUtc) {
                        grant.Ticket.Properties.IssuedUtc = null;
                    }

                    if (grant.Ticket.Properties.ExpiresUtc == ticket.Properties.ExpiresUtc) {
                        grant.Ticket.Properties.ExpiresUtc = null;
                    }

                    ticket = grant.Ticket;
                }
            }

            // See http://tools.ietf.org/html/rfc6749#section-4.3
            // and http://tools.ietf.org/html/rfc6749#section-4.3.2
            else if (request.IsPasswordGrantType()) {
                var grant = new GrantResourceOwnerCredentialsContext(Context, Options, request);
                await Options.Provider.GrantResourceOwnerCredentials(grant);

                if (!grant.IsValidated) {
                    // Note: use invalid_grant as the default error if none has been explicitly provided.
                    return await SendTokenResponseAsync(request, new OpenIdConnectMessage {
                        Error = grant.Error ?? OpenIdConnectConstants.Errors.InvalidGrant,
                        ErrorDescription = grant.ErrorDescription,
                        ErrorUri = grant.ErrorUri
                    });
                }

                ticket = grant.Ticket;
            }

            // See http://tools.ietf.org/html/rfc6749#section-4.4
            // and http://tools.ietf.org/html/rfc6749#section-4.4.2
            else if (request.IsClientCredentialsGrantType()) {
                var grant = new GrantClientCredentialsContext(Context, Options, request);
                await Options.Provider.GrantClientCredentials(grant);

                if (!grant.IsValidated) {
                    // Note: use unauthorized_client as the default error if none has been explicitly provided.
                    return await SendTokenResponseAsync(request, new OpenIdConnectMessage {
                        Error = grant.Error ?? OpenIdConnectConstants.Errors.UnauthorizedClient,
                        ErrorDescription = grant.ErrorDescription,
                        ErrorUri = grant.ErrorUri
                    });
                }

                ticket = grant.Ticket;
            }

            // See http://tools.ietf.org/html/rfc6749#section-8.3
            else {
                var grant = new GrantCustomExtensionContext(Context, Options, request);
                await Options.Provider.GrantCustomExtension(grant);

                if (!grant.IsValidated) {
                    // Note: use unsupported_grant_type as the default error if none has been explicitly provided.
                    return await SendTokenResponseAsync(request, new OpenIdConnectMessage {
                        Error = grant.Error ?? OpenIdConnectConstants.Errors.UnsupportedGrantType,
                        ErrorDescription = grant.ErrorDescription,
                        ErrorUri = grant.ErrorUri
                    });
                }

                ticket = grant.Ticket;
            }

            var notification = new HandleTokenRequestContext(Context, Options, request, ticket);
            await Options.Provider.HandleTokenRequest(notification);

            if (notification.HandledResponse) {
                return true;
            }

            else if (notification.Skipped) {
                return false;
            }

            // Flow the changes made to the ticket.
            ticket = notification.Ticket;

            // Ensure an authentication ticket has been provided:
            // a null ticket MUST result in an internal server error.
            if (ticket == null) {
                Options.Logger.LogError("The token request was rejected because no authentication " +
                                        "ticket was returned by application code.");

                return await SendTokenResponseAsync(request, new OpenIdConnectMessage {
                    Error = OpenIdConnectConstants.Errors.ServerError
                });
            }

            if (context.IsValidated) {
                // Store a boolean indicating whether the ticket should be marked as confidential.
                ticket.Properties.Dictionary[OpenIdConnectConstants.Properties.Confidential] = "true";
            }

            // Always include the "openid" scope when the developer doesn't explicitly call SetScopes.
            // Note: the application is allowed to specify a different "scopes": in this case,
            // don't replace the "scopes" property stored in the authentication ticket.
            if (!ticket.Properties.Dictionary.ContainsKey(OpenIdConnectConstants.Properties.Scopes) &&
                 request.HasScope(OpenIdConnectConstants.Scopes.OpenId)) {
                ticket.Properties.Dictionary[OpenIdConnectConstants.Properties.Scopes] = OpenIdConnectConstants.Scopes.OpenId;
            }

            string audiences;
            // When a "resources" property cannot be found in the authentication properties, infer it from the "audiences" property.
            if (!ticket.Properties.Dictionary.ContainsKey(OpenIdConnectConstants.Properties.Resources) &&
                 ticket.Properties.Dictionary.TryGetValue(OpenIdConnectConstants.Properties.Audiences, out audiences)) {
                ticket.Properties.Dictionary[OpenIdConnectConstants.Properties.Resources] = audiences;
            }

            var response = new OpenIdConnectMessage();

            // Note: by default, an access token is always returned, but the client application can use the "response_type" parameter
            // to only include specific types of tokens. When this parameter is missing, an access token is always generated.
            if (string.IsNullOrEmpty(request.ResponseType) || request.HasResponseType(OpenIdConnectConstants.ResponseTypes.Token)) {
                // Make sure to create a copy of the authentication properties
                // to avoid modifying the properties set on the original ticket.
                var properties = ticket.Properties.Copy();

                // When receiving a grant_type=refresh_token request, determine whether the client application
                // requests a limited set of resources and replace the "resources" property if necessary.
                if (request.IsRefreshTokenGrantType() && !string.IsNullOrEmpty(request.Resource)) {
                    // Replace the resources initially granted by the resources listed by the client application in the token request.
                    // Note: at this stage, request.GetResources() cannot return more items than the ones that were initially granted
                    // by the resource owner as the "resources" parameter is always validated when receiving the token request.
                    properties.Dictionary[OpenIdConnectConstants.Properties.Resources] = string.Join(" ", request.GetResources());
                }

                // Note: when the "resource" parameter added to the OpenID Connect response
                // is identical to the request parameter, returning it is not necessary.
                var resources = properties.GetProperty(OpenIdConnectConstants.Properties.Resources);
                if (request.IsAuthorizationCodeGrantType() || (!string.IsNullOrEmpty(resources) &&
                                                               !string.IsNullOrEmpty(request.Resource) &&
                                                               !string.Equals(request.Resource, resources, StringComparison.Ordinal))) {
                    response.Resource = resources;
                }

                // When receiving a grant_type=refresh_token request, determine whether the client application
                // requests a limited set of scopes and replace the "scopes" property if necessary.
                if (request.IsRefreshTokenGrantType() && !string.IsNullOrEmpty(request.Scope)) {
                    // Replace the scopes initially granted by the scopes listed by the client application in the token request.
                    // Note: at this stage, request.GetScopes() cannot return more items than the ones that were initially granted
                    // by the resource owner as the "scope" parameter is always validated when receiving the token request.
                    properties.Dictionary[OpenIdConnectConstants.Properties.Scopes] = string.Join(" ", request.GetScopes());
                }

                // Note: when the "scope" parameter added to the OpenID Connect response
                // is identical to the request parameter, returning it is not necessary.
                var scopes = properties.GetProperty(OpenIdConnectConstants.Properties.Scopes);
                if (request.IsAuthorizationCodeGrantType() || (!string.IsNullOrEmpty(scopes) &&
                                                               !string.IsNullOrEmpty(request.Scope) &&
                                                               !string.Equals(request.Scope, scopes, StringComparison.Ordinal))) {
                    response.Scope = scopes;
                }

                response.TokenType = OpenIdConnectConstants.TokenTypes.Bearer;
                response.AccessToken = await SerializeAccessTokenAsync(ticket.Identity, properties, request, response);

                // Ensure that an access token is issued to avoid returning an invalid response.
                // See http://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#Combinations
                if (string.IsNullOrEmpty(response.AccessToken)) {
                    Options.Logger.LogError("An error occurred during the serialization of the " +
                                            "access token and a null value was returned.");

                    return await SendTokenResponseAsync(request, new OpenIdConnectMessage {
                        Error = OpenIdConnectConstants.Errors.ServerError,
                        ErrorDescription = "no valid access token was issued"
                    });
                }

                // properties.ExpiresUtc is automatically set by SerializeAccessTokenAsync but the end user
                // is free to set a null value directly in the SerializeAccessToken event.
                if (properties.ExpiresUtc.HasValue && properties.ExpiresUtc > Options.SystemClock.UtcNow) {
                    var lifetime = properties.ExpiresUtc.Value - Options.SystemClock.UtcNow;
                    var expiration = (long) (lifetime.TotalSeconds + .5);

                    response.ExpiresIn = expiration.ToString(CultureInfo.InvariantCulture);
                }
            }

            // Note: by default, an identity token is always returned when the "openid" scope has been requested,
            // but the client application can use the "response_type" parameter to only include specific types of tokens.
            // When this parameter is missing, an identity token is always generated.
            if (ticket.HasScope(OpenIdConnectConstants.Scopes.OpenId) &&
               (string.IsNullOrEmpty(request.ResponseType) || request.HasResponseType(OpenIdConnectConstants.ResponseTypes.IdToken))) {
                // Make sure to create a copy of the authentication properties
                // to avoid modifying the properties set on the original ticket.
                var properties = ticket.Properties.Copy();

                response.IdToken = await SerializeIdentityTokenAsync(ticket.Identity, properties, request, response);

                // Ensure that an identity token is issued to avoid returning an invalid response.
                // See http://openid.net/specs/openid-connect-core-1_0.html#TokenResponse
                // and http://openid.net/specs/openid-connect-core-1_0.html#RefreshTokenResponse
                if (string.IsNullOrEmpty(response.IdToken)) {
                    Options.Logger.LogError("An error occurred during the serialization of the " +
                                            "identity token and a null value was returned.");

                    return await SendTokenResponseAsync(request, new OpenIdConnectMessage {
                        Error = OpenIdConnectConstants.Errors.ServerError,
                        ErrorDescription = "no valid identity token was issued"
                    });
                }
            }

            // Note: by default, a refresh token is always returned when the "offline_access" scope has been requested,
            // but the client application can use the "response_type" parameter to only include specific types of tokens.
            // When this parameter is missing, a refresh token is always generated.
            if (ticket.HasScope(OpenIdConnectConstants.Scopes.OfflineAccess) &&
               (!request.IsRefreshTokenGrantType() || Options.UseSlidingExpiration) &&
               (string.IsNullOrEmpty(request.ResponseType) || request.HasResponseType(OpenIdConnectConstants.Parameters.RefreshToken))) {
                // Make sure to create a copy of the authentication properties
                // to avoid modifying the properties set on the original ticket.
                var properties = ticket.Properties.Copy();

                response.SetRefreshToken(await SerializeRefreshTokenAsync(ticket.Identity, properties, request, response));
            }

            return await SendTokenResponseAsync(request, response, ticket);
        }

        private Task<bool> SendTokenResponseAsync(
            OpenIdConnectMessage request,
            OpenIdConnectMessage response, AuthenticationTicket ticket = null) {
            var payload = new JObject();

            foreach (var parameter in response.Parameters) {
                payload[parameter.Key] = parameter.Value;
            }

            return SendTokenResponseAsync(request, payload);
        }

        private async Task<bool> SendTokenResponseAsync(
            OpenIdConnectMessage request, JObject response, AuthenticationTicket ticket = null) {
            if (request == null) {
                request = new OpenIdConnectMessage();
            }

            var notification = new ApplyTokenResponseContext(Context, Options, ticket, request, response);
            await Options.Provider.ApplyTokenResponse(notification);

            if (notification.HandledResponse) {
                return true;
            }

            else if (notification.Skipped) {
                return false;
            }

            return await SendPayloadAsync(response);
        }
    }
}
