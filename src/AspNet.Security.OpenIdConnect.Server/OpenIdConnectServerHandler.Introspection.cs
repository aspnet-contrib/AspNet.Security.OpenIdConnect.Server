/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Extensions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Net.Http.Headers;
using Newtonsoft.Json.Linq;

namespace AspNet.Security.OpenIdConnect.Server {
    internal partial class OpenIdConnectServerHandler : AuthenticationHandler<OpenIdConnectServerOptions> {
        private async Task<bool> InvokeIntrospectionEndpointAsync() {
            OpenIdConnectMessage request;

            // See https://tools.ietf.org/html/rfc7662#section-2.1
            // and https://tools.ietf.org/html/rfc7662#section-4
            if (string.Equals(Request.Method, "GET", StringComparison.OrdinalIgnoreCase)) {
                request = new OpenIdConnectMessage(Request.Query.ToDictionary());
            }

            else if (string.Equals(Request.Method, "POST", StringComparison.OrdinalIgnoreCase)) {
                // See http://openid.net/specs/openid-connect-core-1_0.html#FormSerialization
                if (string.IsNullOrEmpty(Request.ContentType)) {
                    Logger.LogError("The introspection request was rejected because " +
                                    "the mandatory 'Content-Type' header was missing.");

                    return await SendIntrospectionResponseAsync(null, new OpenIdConnectMessage {
                        Error = OpenIdConnectConstants.Errors.InvalidRequest,
                        ErrorDescription = "A malformed introspection request has been received: " +
                            "the mandatory 'Content-Type' header was missing from the POST request."
                    });
                }

                // May have media/type; charset=utf-8, allow partial match.
                if (!Request.ContentType.StartsWith("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase)) {
                    Logger.LogError("The introspection request was rejected because an invalid 'Content-Type' " +
                                    "header was received: {ContentType}.", Request.ContentType);

                    return await SendIntrospectionResponseAsync(null, new OpenIdConnectMessage {
                        Error = OpenIdConnectConstants.Errors.InvalidRequest,
                        ErrorDescription = "A malformed introspection request has been received: " +
                            "the 'Content-Type' header contained an unexcepted value. " +
                            "Make sure to use 'application/x-www-form-urlencoded'."
                    });
                }

                var form = await Request.ReadFormAsync(Context.RequestAborted);

                request = new OpenIdConnectMessage(form.ToDictionary());
            }

            else {
                Logger.LogError("The introspection request was rejected because an invalid " +
                                "HTTP method was received: {Method}.", Request.Method);

                return await SendIntrospectionResponseAsync(null, new OpenIdConnectMessage {
                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = "A malformed introspection request has been received: " +
                                       "make sure to use either GET or POST."
                });
            }

            var @event = new ExtractIntrospectionRequestContext(Context, Options, request);
            await Options.Provider.ExtractIntrospectionRequest(@event);

            // Allow the application code to replace the introspection request.
            request = @event.Request;

            if (@event.HandledResponse) {
                return true;
            }

            else if (@event.Skipped) {
                return false;
            }

            else if (@event.IsRejected) {
                Logger.LogError("The introspection request was rejected with the following error: {Error} ; {Description}",
                                /* Error: */ @event.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
                                /* Description: */ @event.ErrorDescription);

                return await SendIntrospectionResponseAsync(null, new OpenIdConnectMessage {
                    Error = @event.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = @event.ErrorDescription,
                    ErrorUri = @event.ErrorUri
                });
            }

            // Insert the introspection request in the ASP.NET context.
            Context.SetOpenIdConnectRequest(request);

            if (string.IsNullOrWhiteSpace(request.GetToken())) {
                return await SendIntrospectionResponseAsync(request, new OpenIdConnectMessage {
                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = "A malformed introspection request has been received: " +
                        "a 'token' parameter with an access, refresh, or identity token is required."
                });
            }

            // When client_id and client_secret are both null, try to extract them from the Authorization header.
            // See http://tools.ietf.org/html/rfc6749#section-2.3.1 and
            // http://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication
            if (string.IsNullOrEmpty(request.ClientId) && string.IsNullOrEmpty(request.ClientSecret)) {
                string header = Request.Headers[HeaderNames.Authorization];
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

            var context = new ValidateIntrospectionRequestContext(Context, Options, request);
            await Options.Provider.ValidateIntrospectionRequest(context);

            if (context.HandledResponse) {
                return true;
            }

            else if (context.Skipped) {
                return false;
            }

            else if (context.IsRejected) {
                Logger.LogError("The introspection request was rejected with the following error: {Error} ; {Description}",
                                /* Error: */ context.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
                                /* Description: */ context.ErrorDescription);

                return await SendIntrospectionResponseAsync(request, new OpenIdConnectMessage {
                    Error = context.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = context.ErrorDescription,
                    ErrorUri = context.ErrorUri
                });
            }

            // Ensure that the client_id has been set from the ValidateIntrospectionRequest event.
            else if (context.IsValidated && string.IsNullOrEmpty(request.ClientId)) {
                Logger.LogError("The introspection request was validated but the client_id was not set.");

                return await SendIntrospectionResponseAsync(request, new OpenIdConnectMessage {
                    Error = OpenIdConnectConstants.Errors.ServerError,
                    ErrorDescription = "An internal server error occurred."
                });
            }

            AuthenticationTicket ticket = null;

            // Note: use the "token_type_hint" parameter to determine
            // the type of the token sent by the client application.
            // See https://tools.ietf.org/html/rfc7662#section-2.1
            switch (request.GetTokenTypeHint()) {
                case OpenIdConnectConstants.TokenTypeHints.AccessToken:
                    ticket = await DeserializeAccessTokenAsync(request.GetToken(), request);
                    break;

                case OpenIdConnectConstants.TokenTypeHints.AuthorizationCode:
                    ticket = await DeserializeAuthorizationCodeAsync(request.GetToken(), request);
                    break;

                case OpenIdConnectConstants.TokenTypeHints.IdToken:
                    ticket = await DeserializeIdentityTokenAsync(request.GetToken(), request);
                    break;

                case OpenIdConnectConstants.TokenTypeHints.RefreshToken:
                    ticket = await DeserializeRefreshTokenAsync(request.GetToken(), request);
                    break;
            }

            // Note: if the token can't be found using "token_type_hint",
            // the search must be extended to all supported token types.
            // See https://tools.ietf.org/html/rfc7662#section-2.1
            if (ticket == null) {
                ticket = await DeserializeAccessTokenAsync(request.GetToken(), request) ??
                         await DeserializeAuthorizationCodeAsync(request.GetToken(), request) ??
                         await DeserializeIdentityTokenAsync(request.GetToken(), request) ??
                         await DeserializeRefreshTokenAsync(request.GetToken(), request);
            }

            if (ticket == null) {
                Logger.LogInformation("The introspection request was rejected because the token was invalid.");

                return await SendIntrospectionResponseAsync(request, new JObject {
                    [OpenIdConnectConstants.Claims.Active] = false
                });
            }

            // Note: unlike refresh or identity tokens that can only be validated by client applications,
            // access tokens can be validated by either resource servers or client applications:
            // in both cases, the caller must be authenticated if the ticket is marked as confidential.
            if (context.IsSkipped && ticket.IsConfidential()) {
                Logger.LogError("The introspection request was rejected because the caller was not authenticated.");

                return await SendIntrospectionResponseAsync(request, new JObject {
                    [OpenIdConnectConstants.Claims.Active] = false
                });
            }

            // If the ticket is already expired, directly return active=false.
            if (ticket.Properties.ExpiresUtc.HasValue &&
                ticket.Properties.ExpiresUtc < Options.SystemClock.UtcNow) {
                Logger.LogInformation("The introspection request was rejected because the token was expired.");

                return await SendIntrospectionResponseAsync(request, new JObject {
                    [OpenIdConnectConstants.Claims.Active] = false
                });
            }

            // When a client_id can be inferred from the introspection request,
            // ensure that the client application is a valid audience/presenter.
            if (!string.IsNullOrEmpty(request.ClientId)) {
                if (ticket.IsAuthorizationCode() && ticket.HasPresenter() && !ticket.HasPresenter(request.ClientId)) {
                    Logger.LogError("The introspection request was rejected because the " +
                                    "authorization code was issued to a different client.");

                    return await SendIntrospectionResponseAsync(request, new JObject {
                        [OpenIdConnectConstants.Claims.Active] = false
                    });
                }

                // Ensure the caller is listed as a valid audience or authorized presenter.
                else if (ticket.IsAccessToken() && ticket.HasAudience() && !ticket.HasAudience(request.ClientId) &&
                                                   ticket.HasPresenter() && !ticket.HasPresenter(request.ClientId)) {
                    Logger.LogError("The introspection request was rejected because the access token " +
                                    "was issued to a different client or for another resource server.");

                    return await SendIntrospectionResponseAsync(request, new JObject {
                        [OpenIdConnectConstants.Claims.Active] = false
                    });
                }

                // Reject the request if the caller is not listed as a valid audience.
                else if (ticket.IsIdentityToken() && ticket.HasAudience() && !ticket.HasAudience(request.ClientId)) {
                    Logger.LogError("The introspection request was rejected because the " +
                                    "identity token was issued to a different client.");

                    return await SendIntrospectionResponseAsync(request, new JObject {
                        [OpenIdConnectConstants.Claims.Active] = false
                    });
                }

                // Reject the introspection request if the caller doesn't
                // correspond to the client application the token was issued to.
                else if (ticket.IsRefreshToken() && ticket.HasPresenter() && !ticket.HasPresenter(request.ClientId)) {
                    Logger.LogError("The introspection request was rejected because the " +
                                    "refresh token was issued to a different client.");

                    return await SendIntrospectionResponseAsync(request, new JObject {
                        [OpenIdConnectConstants.Claims.Active] = false
                    });
                }
            }

            var notification = new HandleIntrospectionRequestContext(Context, Options, request, ticket);
            notification.Active = true;

            // Use the unique ticket identifier to populate the "jti" claim.
            notification.TokenId = ticket.GetTicketId();

            // Note: only set "token_type" when the received token is an access token.
            // See https://tools.ietf.org/html/rfc7662#section-2.2
            // and https://tools.ietf.org/html/rfc6749#section-5.1
            if (ticket.IsAccessToken()) {
                notification.TokenType = OpenIdConnectConstants.TokenTypes.Bearer;
            }

            notification.Issuer = Context.GetIssuer(Options);
            notification.Subject = ticket.Principal.GetClaim(ClaimTypes.NameIdentifier);

            notification.IssuedAt = ticket.Properties.IssuedUtc;
            notification.ExpiresAt = ticket.Properties.ExpiresUtc;

            // Copy the audiences extracted from the "aud" claim.
            foreach (var audience in ticket.GetAudiences()) {
                notification.Audiences.Add(audience);
            }

            // Note: non-metadata claims are only added if the caller is authenticated
            // AND is in the specified audiences, unless there's so explicit audience.
            if (!ticket.HasAudience() || (!string.IsNullOrEmpty(request.ClientId) && ticket.HasAudience(request.ClientId))) {
                // Extract the main identity associated with the principal.
                var identity = (ClaimsIdentity) ticket.Principal.Identity;

                notification.Username = identity.Name;
                notification.Scope = ticket.GetProperty(OpenIdConnectConstants.Properties.Scopes);

                // Potentially sensitive claims are only exposed to trusted callers
                // if the ticket corresponds to an access or identity token.
                if (ticket.IsAccessToken() || ticket.IsIdentityToken()) {
                    foreach (var claim in ticket.Principal.Claims) {
                        // Exclude standard claims, that are already handled via strongly-typed properties.
                        // Make sure to always update this list when adding new built-in claim properties.
                        if (string.Equals(claim.Type, identity.NameClaimType, StringComparison.Ordinal) ||
                            string.Equals(claim.Type, ClaimTypes.NameIdentifier, StringComparison.Ordinal)) {
                            continue;
                        }

                        if (string.Equals(claim.Type, OpenIdConnectConstants.Claims.Audience, StringComparison.Ordinal) ||
                            string.Equals(claim.Type, OpenIdConnectConstants.Claims.ExpiresAt, StringComparison.Ordinal) ||
                            string.Equals(claim.Type, OpenIdConnectConstants.Claims.IssuedAt, StringComparison.Ordinal) ||
                            string.Equals(claim.Type, OpenIdConnectConstants.Claims.Issuer, StringComparison.Ordinal) ||
                            string.Equals(claim.Type, OpenIdConnectConstants.Claims.NotBefore, StringComparison.Ordinal) ||
                            string.Equals(claim.Type, OpenIdConnectConstants.Claims.Scope, StringComparison.Ordinal) ||
                            string.Equals(claim.Type, OpenIdConnectConstants.Claims.Subject, StringComparison.Ordinal) ||
                            string.Equals(claim.Type, OpenIdConnectConstants.Claims.TokenType, StringComparison.Ordinal)) {
                            continue;
                        }

                        string type;
                        // Try to resolve the short name associated with the claim type:
                        // if none can be found, the claim type is used as-is.
                        if (!JwtSecurityTokenHandler.DefaultOutboundClaimTypeMap.TryGetValue(claim.Type, out type)) {
                            type = claim.Type;
                        }

                        // If there's no existing claim with the same type,
                        // simply add the claim as-is without converting it.
                        if (!notification.Claims.ContainsKey(type)) {
                            notification.Claims[type] = claim.Value;

                            continue;
                        }

                        // When multiple claims with the same name exist, convert the existing entry
                        // to a new JArray to allow returning multiple claim values to the caller.
                        var array = notification.Claims[type] as JArray;
                        if (array == null) {
                            array = new JArray();

                            // Copy the existing claim value to the new array.
                            array.Add(notification.Claims[type]);

                            // Replace the entry in the claims collection.
                            notification.Claims[type] = array;
                        }

                        // Add the new item in the JArray.
                        array.Add(claim.Value);
                    }
                }
            }

            await Options.Provider.HandleIntrospectionRequest(notification);

            if (notification.HandledResponse) {
                return true;
            }

            else if (notification.Skipped) {
                return false;
            }

            else if (notification.IsRejected) {
                Logger.LogError("The introspection request was rejected with the following error: {Error} ; {Description}",
                                /* Error: */ notification.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
                                /* Description: */ notification.ErrorDescription);

                return await SendIntrospectionResponseAsync(request, new OpenIdConnectMessage {
                    Error = notification.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = notification.ErrorDescription,
                    ErrorUri = notification.ErrorUri
                });
            }

            var response = new JObject();

            response.Add(OpenIdConnectConstants.Claims.Active, notification.Active);

            // Only add the other properties if
            // the token is considered as active.
            if (notification.Active) {
                if (!string.IsNullOrEmpty(notification.Issuer)) {
                    response.Add(OpenIdConnectConstants.Claims.Issuer, notification.Issuer);
                }

                if (!string.IsNullOrEmpty(notification.Username)) {
                    response.Add(OpenIdConnectConstants.Claims.Username, notification.Username);
                }

                if (!string.IsNullOrEmpty(notification.Subject)) {
                    response.Add(OpenIdConnectConstants.Claims.Subject, notification.Subject);
                }

                if (!string.IsNullOrEmpty(notification.Scope)) {
                    response.Add(OpenIdConnectConstants.Claims.Scope, notification.Scope);
                }

                if (notification.IssuedAt.HasValue) {
                    response.Add(OpenIdConnectConstants.Claims.IssuedAt,
                        EpochTime.GetIntDate(notification.IssuedAt.Value.UtcDateTime));

                    response.Add(OpenIdConnectConstants.Claims.NotBefore,
                        EpochTime.GetIntDate(notification.IssuedAt.Value.UtcDateTime));
                }

                if (notification.ExpiresAt.HasValue) {
                    response.Add(OpenIdConnectConstants.Claims.ExpiresAt,
                        EpochTime.GetIntDate(notification.ExpiresAt.Value.UtcDateTime));
                }

                if (!string.IsNullOrEmpty(notification.TokenId)) {
                    response.Add(OpenIdConnectConstants.Claims.JwtId, notification.TokenId);
                }

                if (!string.IsNullOrEmpty(notification.TokenType)) {
                    response.Add(OpenIdConnectConstants.Claims.TokenType, notification.TokenType);
                }

                switch (notification.Audiences.Count) {
                    case 0: break;

                    case 1:
                        response.Add(OpenIdConnectConstants.Claims.Audience, notification.Audiences[0]);
                        break;

                    default:
                        response.Add(OpenIdConnectConstants.Claims.Audience, JArray.FromObject(notification.Audiences));
                        break;
                }

                foreach (var claim in notification.Claims) {
                    // Ignore claims whose value is null.
                    if (claim.Value == null) {
                        continue;
                    }

                    // Note: make sure to use the indexer
                    // syntax to avoid duplicate properties.
                    response[claim.Key] = claim.Value;
                }
            }

            return await SendIntrospectionResponseAsync(request, response);
        }

        private Task<bool> SendIntrospectionResponseAsync(OpenIdConnectMessage request, OpenIdConnectMessage response) {
            var payload = new JObject();

            foreach (var parameter in response.Parameters) {
                payload[parameter.Key] = parameter.Value;
            }

            return SendIntrospectionResponseAsync(request, payload);
        }

        private async Task<bool> SendIntrospectionResponseAsync(OpenIdConnectMessage request, JObject response) {
            if (request == null) {
                request = new OpenIdConnectMessage();
            }

            var notification = new ApplyIntrospectionResponseContext(Context, Options, request, response);
            await Options.Provider.ApplyIntrospectionResponse(notification);

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