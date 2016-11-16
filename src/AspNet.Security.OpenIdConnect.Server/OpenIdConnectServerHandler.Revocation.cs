/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.Text;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Extensions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Logging;
using Microsoft.Net.Http.Headers;

namespace AspNet.Security.OpenIdConnect.Server {
    internal partial class OpenIdConnectServerHandler : AuthenticationHandler<OpenIdConnectServerOptions> {
        private async Task<bool> InvokeRevocationEndpointAsync() {
            if (!string.Equals(Request.Method, "POST", StringComparison.OrdinalIgnoreCase)) {
                Logger.LogError("The revocation request was rejected because an invalid " +
                                "HTTP method was received: {Method}.", Request.Method);

                return await SendRevocationResponseAsync(new OpenIdConnectResponse {
                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = "A malformed revocation request has been received: " +
                                       "make sure to use either GET or POST."
                });
            }

            // See http://openid.net/specs/openid-connect-core-1_0.html#FormSerialization
            if (string.IsNullOrEmpty(Request.ContentType)) {
                Logger.LogError("The revocation request was rejected because " +
                                "the mandatory 'Content-Type' header was missing.");

                return await SendRevocationResponseAsync(new OpenIdConnectResponse {
                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = "A malformed revocation request has been received: " +
                        "the mandatory 'Content-Type' header was missing from the POST request."
                });
            }

            // May have media/type; charset=utf-8, allow partial match.
            if (!Request.ContentType.StartsWith("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase)) {
                Logger.LogError("The revocation request was rejected because an invalid 'Content-Type' " +
                                "header was received: {ContentType}.", Request.ContentType);

                return await SendRevocationResponseAsync(new OpenIdConnectResponse {
                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = "A malformed revocation request has been received: " +
                        "the 'Content-Type' header contained an unexcepted value. " +
                        "Make sure to use 'application/x-www-form-urlencoded'."
                });
            }

            var request = new OpenIdConnectRequest(await Request.ReadFormAsync(Context.RequestAborted));

            // Note: set the message type before invoking the ExtractRevocationRequest event.
            request.SetProperty(OpenIdConnectConstants.Properties.MessageType,
                                OpenIdConnectConstants.MessageTypes.Revocation);

            // Insert the revocation request in the ASP.NET context.
            Context.SetOpenIdConnectRequest(request);

            var @event = new ExtractRevocationRequestContext(Context, Options, request);
            await Options.Provider.ExtractRevocationRequest(@event);

            if (@event.HandledResponse) {
                return true;
            }

            else if (@event.Skipped) {
                return false;
            }

            else if (@event.IsRejected) {
                Logger.LogError("The revocation request was rejected with the following error: {Error} ; {Description}",
                                /* Error: */ @event.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
                                /* Description: */ @event.ErrorDescription);

                return await SendRevocationResponseAsync(new OpenIdConnectResponse {
                    Error = @event.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = @event.ErrorDescription,
                    ErrorUri = @event.ErrorUri
                });
            }

            if (string.IsNullOrWhiteSpace(request.Token)) {
                return await SendRevocationResponseAsync(new OpenIdConnectResponse {
                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = "A malformed revocation request has been received: " +
                        "a 'token' parameter with an access or refresh token is required."
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

            var context = new ValidateRevocationRequestContext(Context, Options, request);
            await Options.Provider.ValidateRevocationRequest(context);

            // If the validation context was set as fully validated,
            // mark the OpenID Connect request as confidential.
            if (context.IsValidated) {
                request.SetProperty(OpenIdConnectConstants.Properties.ConfidentialityLevel,
                                    OpenIdConnectConstants.ConfidentialityLevels.Private);
            }

            if (context.HandledResponse) {
                return true;
            }

            else if (context.Skipped) {
                return false;
            }

            else if (context.IsRejected) {
                Logger.LogError("The revocation request was rejected with the following error: {Error} ; {Description}",
                                /* Error: */ context.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
                                /* Description: */ context.ErrorDescription);

                return await SendRevocationResponseAsync(new OpenIdConnectResponse {
                    Error = context.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = context.ErrorDescription,
                    ErrorUri = context.ErrorUri
                });
            }

            // Ensure that the client_id has been set from the ValidateRevocationRequest event.
            else if (context.IsValidated && string.IsNullOrEmpty(request.ClientId)) {
                Logger.LogError("The revocation request was validated but the client_id was not set.");

                return await SendRevocationResponseAsync(new OpenIdConnectResponse {
                    Error = OpenIdConnectConstants.Errors.ServerError,
                    ErrorDescription = "An internal server error occurred."
                });
            }

            AuthenticationTicket ticket = null;

            // Note: use the "token_type_hint" parameter to determine
            // the type of the token sent by the client application.
            // See https://tools.ietf.org/html/rfc7009#section-2.1
            switch (request.TokenTypeHint) {
                case OpenIdConnectConstants.TokenTypeHints.AccessToken:
                    ticket = await DeserializeAccessTokenAsync(request.Token, request);
                    break;

                case OpenIdConnectConstants.TokenTypeHints.AuthorizationCode:
                    ticket = await DeserializeAuthorizationCodeAsync(request.Token, request);
                    break;

                case OpenIdConnectConstants.TokenTypeHints.IdToken:
                    ticket = await DeserializeIdentityTokenAsync(request.Token, request);
                    break;

                case OpenIdConnectConstants.TokenTypeHints.RefreshToken:
                    ticket = await DeserializeRefreshTokenAsync(request.Token, request);
                    break;
            }

            // Note: if the token can't be found using "token_type_hint",
            // the search must be extended to all supported token types.
            // See https://tools.ietf.org/html/rfc7009#section-2.1
            if (ticket == null) {
                ticket = await DeserializeAccessTokenAsync(request.Token, request) ??
                         await DeserializeAuthorizationCodeAsync(request.Token, request) ??
                         await DeserializeIdentityTokenAsync(request.Token, request) ??
                         await DeserializeRefreshTokenAsync(request.Token, request);
            }

            if (ticket == null) {
                Logger.LogInformation("The revocation request was ignored because the token was invalid.");

                return await SendRevocationResponseAsync(new OpenIdConnectResponse());
            }

            // If the ticket is already expired, directly return a 200 response.
            else if (ticket.Properties.ExpiresUtc.HasValue &&
                     ticket.Properties.ExpiresUtc < Options.SystemClock.UtcNow) {
                Logger.LogInformation("The revocation request was ignored because the token was already expired.");

                return await SendRevocationResponseAsync(new OpenIdConnectResponse());
            }

            // Note: unlike refresh tokens that can only be revoked by client applications,
            // access tokens can be revoked by either resource servers or client applications:
            // in both cases, the caller must be authenticated if the ticket is marked as confidential.
            if (context.IsSkipped && ticket.IsConfidential()) {
                Logger.LogError("The revocation request was rejected because the caller was not authenticated.");

                return await SendRevocationResponseAsync(new OpenIdConnectResponse {
                    Error = OpenIdConnectConstants.Errors.InvalidRequest
                });
            }

            // When a client_id can be inferred from the introspection request,
            // ensure that the client application is a valid audience/presenter.
            if (!string.IsNullOrEmpty(request.ClientId)) {
                if (ticket.IsAuthorizationCode() && ticket.HasPresenter() && !ticket.HasPresenter(request.ClientId)) {
                    Logger.LogError("The revocation request was rejected because the " +
                                    "authorization code was issued to a different client.");

                    return await SendRevocationResponseAsync(new OpenIdConnectResponse {
                        Error = OpenIdConnectConstants.Errors.InvalidRequest
                    });
                }

                // Ensure the caller is listed as a valid audience or authorized presenter.
                else if (ticket.IsAccessToken() && ticket.HasAudience() && !ticket.HasAudience(request.ClientId) &&
                                                   ticket.HasPresenter() && !ticket.HasPresenter(request.ClientId)) {
                    Logger.LogError("The revocation request was rejected because the access token " +
                                    "was issued to a different client or for another resource server.");

                    return await SendRevocationResponseAsync(new OpenIdConnectResponse {
                        Error = OpenIdConnectConstants.Errors.InvalidRequest
                    });
                }

                // Reject the request if the caller is not listed as a valid audience.
                else if (ticket.IsIdentityToken() && ticket.HasAudience() && !ticket.HasAudience(request.ClientId)) {
                    Logger.LogError("The revocation request was rejected because the " +
                                    "identity token was issued to a different client.");

                    return await SendRevocationResponseAsync(new OpenIdConnectResponse {
                        Error = OpenIdConnectConstants.Errors.InvalidRequest
                    });
                }

                // Reject the introspection request if the caller doesn't
                // correspond to the client application the token was issued to.
                else if (ticket.IsRefreshToken() && ticket.HasPresenter() && !ticket.HasPresenter(request.ClientId)) {
                    Logger.LogError("The revocation request was rejected because the " +
                                    "refresh token was issued to a different client.");

                    return await SendRevocationResponseAsync(new OpenIdConnectResponse {
                        Error = OpenIdConnectConstants.Errors.InvalidRequest
                    });
                }
            }

            var notification = new HandleRevocationRequestContext(Context, Options, request, ticket);
            await Options.Provider.HandleRevocationRequest(notification);

            if (notification.HandledResponse) {
                return true;
            }

            else if (notification.Skipped) {
                return false;
            }

            else if (notification.IsRejected) {
                Logger.LogError("The revocation request was rejected with the following error: {Error} ; {Description}",
                                /* Error: */ notification.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
                                /* Description: */ notification.ErrorDescription);

                return await SendRevocationResponseAsync(new OpenIdConnectResponse {
                    Error = notification.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = notification.ErrorDescription,
                    ErrorUri = notification.ErrorUri
                });
            }

            if (!notification.Revoked) {
                return await SendRevocationResponseAsync(new OpenIdConnectResponse {
                    Error = OpenIdConnectConstants.Errors.UnsupportedTokenType,
                    ErrorDescription = "The token cannot be revoked."
                });
            }

            return await SendRevocationResponseAsync(new OpenIdConnectResponse());
        }

        private async Task<bool> SendRevocationResponseAsync(OpenIdConnectResponse response) {
            var request = Context.GetOpenIdConnectRequest();
            if (request == null) {
                request = new OpenIdConnectRequest();
            }

            Context.SetOpenIdConnectResponse(response);

            var notification = new ApplyRevocationResponseContext(Context, Options, request, response);
            await Options.Provider.ApplyRevocationResponse(notification);

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
