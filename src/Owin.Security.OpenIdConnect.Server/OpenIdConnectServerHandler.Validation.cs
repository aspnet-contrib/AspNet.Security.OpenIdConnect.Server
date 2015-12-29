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
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Protocols;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Owin.Security.OpenIdConnect.Extensions;

namespace Owin.Security.OpenIdConnect.Server {
    internal partial class OpenIdConnectServerHandler : AuthenticationHandler<OpenIdConnectServerOptions> {
        private async Task InvokeValidationEndpointAsync() {
            OpenIdConnectMessage request;

            // See https://tools.ietf.org/html/rfc7662#section-2.1
            // and https://tools.ietf.org/html/rfc7662#section-4
            if (string.Equals(Request.Method, "GET", StringComparison.OrdinalIgnoreCase)) {
                request = new OpenIdConnectMessage(Request.Query) {
                    RequestType = OpenIdConnectRequestType.AuthenticationRequest
                };
            }

            else if (string.Equals(Request.Method, "POST", StringComparison.OrdinalIgnoreCase)) {
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

            else {
                Options.Logger.WriteInformation("A malformed request has been received by the validation endpoint.");

                await SendErrorPageAsync(new OpenIdConnectMessage {
                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = "A malformed validation request has been received: " +
                                       "make sure to use either GET or POST."
                });

                return;
            }

            if (string.IsNullOrWhiteSpace(request.Token)) {
                await SendErrorPayloadAsync(new OpenIdConnectMessage {
                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = "A malformed validation request has been received: " +
                        "a 'token' parameter with an access, refresh, or identity token is required."
                });

                return;
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

            var clientNotification = new ValidateClientAuthenticationContext(Context, Options, request);
            await Options.Provider.ValidateClientAuthentication(clientNotification);

            // Reject the request if client authentication was rejected.
            if (clientNotification.IsRejected) {
                Options.Logger.WriteError("The validation request was rejected " +
                                          "because client authentication was invalid.");

                await SendPayloadAsync(new JObject {
                    [OpenIdConnectConstants.Claims.Active] = false
                });

                return;
            }

            // Ensure that the client_id has been set from the ValidateClientAuthentication event.
            else if (clientNotification.IsValidated && string.IsNullOrEmpty(request.ClientId)) {
                Options.Logger.WriteError("Client authentication was validated but the client_id was not set.");

                await SendErrorPayloadAsync(new OpenIdConnectMessage {
                    Error = OpenIdConnectConstants.Errors.ServerError,
                    ErrorDescription = "An internal server error occurred."
                });

                return;
            }

            AuthenticationTicket ticket = null;

            // Note: use the "token_type_hint" parameter to determine
            // the type of the token sent by the client application.
            // See https://tools.ietf.org/html/rfc7662#section-2.1
            switch (request.GetTokenTypeHint()) {
                case OpenIdConnectConstants.Usages.AccessToken:
                    ticket = await DeserializeAccessTokenAsync(request.Token, request);
                    break;

                case OpenIdConnectConstants.Usages.RefreshToken:
                    ticket = await DeserializeRefreshTokenAsync(request.Token, request);
                    break;

                case OpenIdConnectConstants.Usages.IdToken:
                    ticket = await DeserializeIdentityTokenAsync(request.Token, request);
                    break;
            }

            // Note: if the token can't be found using "token_type_hint",
            // the search must be extended to all supported token types.
            // See https://tools.ietf.org/html/rfc7662#section-2.1
            if (ticket == null) {
                ticket = await DeserializeAccessTokenAsync(request.Token, request) ??
                         await DeserializeIdentityTokenAsync(request.Token, request) ??
                         await DeserializeRefreshTokenAsync(request.Token, request);
            }

            if (ticket == null) {
                Options.Logger.WriteInformation("The validation request was rejected because the token was invalid.");

                await SendPayloadAsync(new JObject {
                    [OpenIdConnectConstants.Claims.Active] = false
                });

                return;
            }

            // Note: unlike refresh or identity tokens that can only be validated by client applications,
            // access tokens can be validated by either resource servers or client applications:
            // in both cases, the caller must be authenticated if the ticket is marked as confidential.
            if (clientNotification.IsSkipped && ticket.IsConfidential()) {
                Options.Logger.WriteWarning("The validation request was rejected " +
                                            "because the caller was not authenticated.");

                await SendPayloadAsync(new JObject {
                    [OpenIdConnectConstants.Claims.Active] = false
                });

                return;
            }

            // If the ticket is already expired, directly return active=false.
            if (ticket.Properties.ExpiresUtc.HasValue &&
                ticket.Properties.ExpiresUtc < Options.SystemClock.UtcNow) {
                Options.Logger.WriteVerbose("expired token");

                await SendPayloadAsync(new JObject {
                    [OpenIdConnectConstants.Claims.Active] = false
                });

                return;
            }

            switch (ticket.GetUsage()) {
                case OpenIdConnectConstants.Usages.AccessToken: {
                    // When the caller is authenticated, ensure it is
                    // listed as a valid audience or authorized presenter.
                    if (clientNotification.IsValidated && !ticket.HasAudience(clientNotification.ClientId) &&
                                                          !ticket.HasPresenter(clientNotification.ClientId)) {
                        Options.Logger.WriteWarning("The validation request was rejected because the access token " +
                                                    "was issued to a different client or for another resource server.");

                        await SendPayloadAsync(new JObject {
                            [OpenIdConnectConstants.Claims.Active] = false
                        });

                        return;
                    }

                    break;
                }

                case OpenIdConnectConstants.Usages.IdToken: {
                    // When the caller is authenticated, reject the validation
                    // request if the caller is not listed as a valid audience.
                    if (clientNotification.IsValidated && !ticket.HasAudience(clientNotification.ClientId)) {
                        Options.Logger.WriteWarning("The validation request was rejected because the " +
                                                    "identity token was issued to a different client.");

                        await SendPayloadAsync(new JObject {
                            [OpenIdConnectConstants.Claims.Active] = false
                        });

                        return;
                    }

                    break;
                }

                case OpenIdConnectConstants.Usages.RefreshToken: {
                    // When the caller is authenticated, reject the validation request if the caller
                    // doesn't correspond to the client application the token was issued to.
                    if (clientNotification.IsValidated && !ticket.HasPresenter(clientNotification.ClientId)) {
                        Options.Logger.WriteWarning("The validation request was rejected because the " +
                                                    "refresh token was issued to a different client.");

                        await SendPayloadAsync(new JObject {
                            [OpenIdConnectConstants.Claims.Active] = false
                        });

                        return;
                    }

                    break;
                }
            }

            // Insert the validation request in the ASP.NET context.
            Context.SetOpenIdConnectRequest(request);

            var notification = new ValidationEndpointContext(Context, Options, request, ticket);
            notification.Active = true;

            // Note: "token_type" may be null when the received token is not an access token.
            // See https://tools.ietf.org/html/rfc7662#section-2.2 and https://tools.ietf.org/html/rfc6749#section-5.1
            notification.TokenType = ticket.Identity.GetClaim(OpenIdConnectConstants.Claims.TokenType);

            notification.Issuer = Context.GetIssuer(Options);
            notification.Subject = ticket.Identity.GetClaim(ClaimTypes.NameIdentifier);

            notification.IssuedAt = ticket.Properties.IssuedUtc;
            notification.ExpiresAt = ticket.Properties.ExpiresUtc;

            // Copy the audiences extracted from the "aud" claim.
            foreach (var audience in ticket.GetAudiences()) {
                notification.Audiences.Add(audience);
            }

            // Note: non-metadata claims are only added if the caller is authenticated AND is in the specified audiences.
            if (clientNotification.IsValidated && notification.Audiences.Contains(clientNotification.ClientId)) {
                notification.Username = ticket.Identity.Name;
                notification.Scope = ticket.GetProperty(OpenIdConnectConstants.Properties.Scopes);

                // Potentially sensitive claims are only exposed to trusted callers
                // if the ticket corresponds to an access or identity token.
                if (ticket.IsAccessToken() || ticket.IsIdentityToken()) {
                    foreach (var claim in ticket.Identity.Claims) {
                        // Exclude standard claims, that are already handled via strongly-typed properties.
                        // Make sure to always update this list when adding new built-in claim properties.
                        if (string.Equals(claim.Type, ticket.Identity.NameClaimType, StringComparison.Ordinal) ||
                            string.Equals(claim.Type, ClaimTypes.NameIdentifier, StringComparison.Ordinal)) {
                            continue;
                        }

                        if (string.Equals(claim.Type, JwtRegisteredClaimNames.Aud, StringComparison.Ordinal) ||
                            string.Equals(claim.Type, JwtRegisteredClaimNames.Exp, StringComparison.Ordinal) ||
                            string.Equals(claim.Type, JwtRegisteredClaimNames.Iat, StringComparison.Ordinal) ||
                            string.Equals(claim.Type, JwtRegisteredClaimNames.Iss, StringComparison.Ordinal) ||
                            string.Equals(claim.Type, JwtRegisteredClaimNames.Nbf, StringComparison.Ordinal) ||
                            string.Equals(claim.Type, JwtRegisteredClaimNames.Sub, StringComparison.Ordinal)) {
                            continue;
                        }

                        if (string.Equals(claim.Type, OpenIdConnectConstants.Claims.TokenType, StringComparison.Ordinal) ||
                            string.Equals(claim.Type, OpenIdConnectConstants.Claims.Scope, StringComparison.Ordinal)) {
                            continue;
                        }

                        string type;
                        // Try to resolve the short name associated with the claim type:
                        // if none can be found, the claim type is used as-is.
                        if (!JwtSecurityTokenHandler.OutboundClaimTypeMap.TryGetValue(claim.Type, out type)) {
                            type = claim.Type;
                        }

                        // Note: make sure to use the indexer
                        // syntax to avoid duplicate properties.
                        notification.Claims[type] = claim.Value;
                    }
                }
            }

            await Options.Provider.ValidationEndpoint(notification);

            // Flow the changes made to the authentication ticket.
            ticket = notification.AuthenticationTicket;

            if (notification.HandledResponse) {
                return;
            }

            var payload = new JObject();

            payload.Add(OpenIdConnectConstants.Claims.Active, notification.Active);

            // Only add the other properties if
            // the token is considered as active.
            if (notification.Active) {
                if (!string.IsNullOrEmpty(notification.Issuer)) {
                    payload.Add(JwtRegisteredClaimNames.Iss, notification.Issuer);
                }

                if (!string.IsNullOrEmpty(notification.Username)) {
                    payload.Add(OpenIdConnectConstants.Claims.Username, notification.Username);
                }

                if (!string.IsNullOrEmpty(notification.Subject)) {
                    payload.Add(JwtRegisteredClaimNames.Sub, notification.Subject);
                }

                if (!string.IsNullOrEmpty(notification.Scope)) {
                    payload.Add(OpenIdConnectConstants.Claims.Scope, notification.Scope);
                }

                if (notification.IssuedAt.HasValue) {
                    payload.Add(JwtRegisteredClaimNames.Iat, EpochTime.GetIntDate(notification.IssuedAt.Value.UtcDateTime));
                    payload.Add(JwtRegisteredClaimNames.Nbf, EpochTime.GetIntDate(notification.IssuedAt.Value.UtcDateTime));
                }

                if (notification.ExpiresAt.HasValue) {
                    payload.Add(JwtRegisteredClaimNames.Exp, EpochTime.GetIntDate(notification.ExpiresAt.Value.UtcDateTime));
                }

                if (!string.IsNullOrEmpty(notification.TokenType)) {
                    payload.Add(OpenIdConnectConstants.Claims.TokenType, notification.TokenType);
                }

                switch (notification.Audiences.Count) {
                    case 0: break;

                    case 1:
                        payload.Add(JwtRegisteredClaimNames.Aud, notification.Audiences[0]);
                        break;

                    default:
                        payload.Add(JwtRegisteredClaimNames.Aud, JArray.FromObject(notification.Audiences));
                        break;
                }

                foreach (var claim in notification.Claims) {
                    // Ignore claims whose value is null.
                    if (claim.Value == null) {
                        continue;
                    }

                    // Note: make sure to use the indexer
                    // syntax to avoid duplicate properties.
                    payload[claim.Key] = claim.Value;
                }
            }

            var context = new ValidationEndpointResponseContext(Context, Options, payload);
            await Options.Provider.ValidationEndpointResponse(context);

            if (context.HandledResponse) {
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
                await buffer.CopyToAsync(Response.Body, 4096, Request.CallCancelled);
            }
        }
    }
}
