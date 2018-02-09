/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Extensions;
using AspNet.Security.OpenIdConnect.Primitives;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace AspNet.Security.OpenIdConnect.Server
{
    public partial class OpenIdConnectServerHandler
    {
        private async Task<bool> InvokeRevocationEndpointAsync()
        {
            if (!HttpMethods.IsPost(Request.Method))
            {
                Logger.LogError("The revocation request was rejected because an invalid " +
                                "HTTP method was specified: {Method}.", Request.Method);

                return await SendRevocationResponseAsync(new OpenIdConnectResponse
                {
                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = "The specified HTTP method is not valid."
                });
            }

            // See http://openid.net/specs/openid-connect-core-1_0.html#FormSerialization
            if (string.IsNullOrEmpty(Request.ContentType))
            {
                Logger.LogError("The revocation request was rejected because " +
                                "the mandatory 'Content-Type' header was missing.");

                return await SendRevocationResponseAsync(new OpenIdConnectResponse
                {
                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = "The mandatory 'Content-Type' header must be specified."
                });
            }

            // May have media/type; charset=utf-8, allow partial match.
            if (!Request.ContentType.StartsWith("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase))
            {
                Logger.LogError("The revocation request was rejected because an invalid 'Content-Type' " +
                                "header was specified: {ContentType}.", Request.ContentType);

                return await SendRevocationResponseAsync(new OpenIdConnectResponse
                {
                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = "The specified 'Content-Type' header is not valid."
                });
            }

            var request = new OpenIdConnectRequest(await Request.ReadFormAsync(Context.RequestAborted));

            // Note: set the message type before invoking the ExtractRevocationRequest event.
            request.SetProperty(OpenIdConnectConstants.Properties.MessageType,
                                OpenIdConnectConstants.MessageTypes.RevocationRequest);

            // Insert the revocation request in the ASP.NET context.
            Context.SetOpenIdConnectRequest(request);

            var @event = new ExtractRevocationRequestContext(Context, Scheme, Options, request);
            await Provider.ExtractRevocationRequest(@event);

            if (@event.Result != null)
            {
                if (@event.Result.Handled)
                {
                    Logger.LogDebug("The revocation request was handled in user code.");

                    return true;
                }

                else if (@event.Result.Skipped)
                {
                    Logger.LogDebug("The default revocation request handling was skipped from user code.");

                    return false;
                }
            }

            else if (@event.IsRejected)
            {
                Logger.LogError("The revocation request was rejected with the following error: {Error} ; {Description}",
                                /* Error: */ @event.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
                                /* Description: */ @event.ErrorDescription);

                return await SendRevocationResponseAsync(new OpenIdConnectResponse
                {
                    Error = @event.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = @event.ErrorDescription,
                    ErrorUri = @event.ErrorUri
                });
            }

            Logger.LogInformation("The revocation request was successfully extracted " +
                                  "from the HTTP request: {Request}.", request);

            if (string.IsNullOrEmpty(request.Token))
            {
                return await SendRevocationResponseAsync(new OpenIdConnectResponse
                {
                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = "The mandatory 'token' parameter is missing."
                });
            }

            // Try to resolve the client credentials specified in the 'Authorization' header.
            // If they cannot be extracted, fallback to the client_id/client_secret parameters.
            var credentials = Request.Headers.GetClientCredentials();
            if (credentials != null)
            {
                // Reject requests that use multiple client authentication methods.
                // See https://tools.ietf.org/html/rfc6749#section-2.3 for more information.
                if (!string.IsNullOrEmpty(request.ClientSecret))
                {
                    Logger.LogError("The revocation request was rejected because " +
                                    "multiple client credentials were specified.");

                    return await SendRevocationResponseAsync(new OpenIdConnectResponse
                    {
                        Error = OpenIdConnectConstants.Errors.InvalidRequest,
                        ErrorDescription = "Multiple client credentials cannot be specified."
                    });
                }

                request.ClientId = credentials?.Key;
                request.ClientSecret = credentials?.Value;
            }

            var context = new ValidateRevocationRequestContext(Context, Scheme, Options, request);
            await Provider.ValidateRevocationRequest(context);

            // If the validation context was set as fully validated,
            // mark the OpenID Connect request as confidential.
            if (context.IsValidated)
            {
                request.SetProperty(OpenIdConnectConstants.Properties.ConfidentialityLevel,
                                    OpenIdConnectConstants.ConfidentialityLevels.Private);
            }

            if (context.Result != null)
            {
                if (context.Result.Handled)
                {
                    Logger.LogDebug("The revocation request was handled in user code.");

                    return true;
                }

                else if (context.Result.Skipped)
                {
                    Logger.LogDebug("The default revocation request handling was skipped from user code.");

                    return false;
                }
            }

            else if (context.IsRejected)
            {
                Logger.LogError("The revocation request was rejected with the following error: {Error} ; {Description}",
                                /* Error: */ context.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
                                /* Description: */ context.ErrorDescription);

                return await SendRevocationResponseAsync(new OpenIdConnectResponse
                {
                    Error = context.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = context.ErrorDescription,
                    ErrorUri = context.ErrorUri
                });
            }

            // Store the validated client_id as a request property.
            request.SetProperty(OpenIdConnectConstants.Properties.ValidatedClientId, context.ClientId);

            Logger.LogInformation("The revocation request was successfully validated.");

            AuthenticationTicket ticket = null;

            // Note: use the "token_type_hint" parameter to determine
            // the type of the token sent by the client application.
            // See https://tools.ietf.org/html/rfc7009#section-2.1
            switch (request.TokenTypeHint)
            {
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
            if (ticket == null)
            {
                // To avoid calling the same deserialization methods twice,
                // an additional check is made to exclude the corresponding
                // method when an explicit token_type_hint was specified.
                switch (request.TokenTypeHint)
                {
                    case OpenIdConnectConstants.TokenTypeHints.AccessToken:
                        ticket = await DeserializeAuthorizationCodeAsync(request.Token, request) ??
                                 await DeserializeIdentityTokenAsync(request.Token, request) ??
                                 await DeserializeRefreshTokenAsync(request.Token, request);
                        break;

                    case OpenIdConnectConstants.TokenTypeHints.AuthorizationCode:
                        ticket = await DeserializeAccessTokenAsync(request.Token, request) ??
                                 await DeserializeIdentityTokenAsync(request.Token, request) ??
                                 await DeserializeRefreshTokenAsync(request.Token, request);
                        break;

                    case OpenIdConnectConstants.TokenTypeHints.IdToken:
                        ticket = await DeserializeAccessTokenAsync(request.Token, request) ??
                                 await DeserializeAuthorizationCodeAsync(request.Token, request) ??
                                 await DeserializeRefreshTokenAsync(request.Token, request);
                        break;

                    case OpenIdConnectConstants.TokenTypeHints.RefreshToken:
                        ticket = await DeserializeAccessTokenAsync(request.Token, request) ??
                                 await DeserializeAuthorizationCodeAsync(request.Token, request) ??
                                 await DeserializeIdentityTokenAsync(request.Token, request);
                        break;

                    default:
                        ticket = await DeserializeAccessTokenAsync(request.Token, request) ??
                                 await DeserializeAuthorizationCodeAsync(request.Token, request) ??
                                 await DeserializeIdentityTokenAsync(request.Token, request) ??
                                 await DeserializeRefreshTokenAsync(request.Token, request);
                        break;
                }
            }

            if (ticket == null)
            {
                Logger.LogInformation("The revocation request was ignored because the token was invalid.");

                return await SendRevocationResponseAsync(new OpenIdConnectResponse());
            }

            // If the ticket is already expired, directly return a 200 response.
            else if (ticket.Properties.ExpiresUtc.HasValue &&
                     ticket.Properties.ExpiresUtc < Options.SystemClock.UtcNow)
            {
                Logger.LogInformation("The revocation request was ignored because the token was already expired.");

                return await SendRevocationResponseAsync(new OpenIdConnectResponse());
            }

            // Note: unlike refresh tokens that can only be revoked by client applications,
            // access tokens can be revoked by either resource servers or client applications:
            // in both cases, the caller must be authenticated if the ticket is marked as confidential.
            if (context.IsSkipped && ticket.IsConfidential())
            {
                Logger.LogError("The revocation request was rejected because the caller was not authenticated.");

                return await SendRevocationResponseAsync(new OpenIdConnectResponse
                {
                    Error = OpenIdConnectConstants.Errors.InvalidRequest
                });
            }

            // When a client_id can be inferred from the introspection request,
            // ensure that the client application is a valid audience/presenter.
            if (!string.IsNullOrEmpty(context.ClientId))
            {
                if (ticket.IsAuthorizationCode() && ticket.HasPresenter() && !ticket.HasPresenter(context.ClientId))
                {
                    Logger.LogError("The revocation request was rejected because the " +
                                    "authorization code was issued to a different client.");

                    return await SendRevocationResponseAsync(new OpenIdConnectResponse
                    {
                        Error = OpenIdConnectConstants.Errors.InvalidRequest
                    });
                }

                // Ensure the caller is listed as a valid audience or authorized presenter.
                else if (ticket.IsAccessToken() && ticket.HasAudience() && !ticket.HasAudience(context.ClientId) &&
                                                   ticket.HasPresenter() && !ticket.HasPresenter(context.ClientId))
                {
                    Logger.LogError("The revocation request was rejected because the access token " +
                                    "was issued to a different client or for another resource server.");

                    return await SendRevocationResponseAsync(new OpenIdConnectResponse
                    {
                        Error = OpenIdConnectConstants.Errors.InvalidRequest
                    });
                }

                // Reject the request if the caller is not listed as a valid audience.
                else if (ticket.IsIdentityToken() && ticket.HasAudience() && !ticket.HasAudience(context.ClientId))
                {
                    Logger.LogError("The revocation request was rejected because the " +
                                    "identity token was issued to a different client.");

                    return await SendRevocationResponseAsync(new OpenIdConnectResponse
                    {
                        Error = OpenIdConnectConstants.Errors.InvalidRequest
                    });
                }

                // Reject the introspection request if the caller doesn't
                // correspond to the client application the token was issued to.
                else if (ticket.IsRefreshToken() && ticket.HasPresenter() && !ticket.HasPresenter(context.ClientId))
                {
                    Logger.LogError("The revocation request was rejected because the " +
                                    "refresh token was issued to a different client.");

                    return await SendRevocationResponseAsync(new OpenIdConnectResponse
                    {
                        Error = OpenIdConnectConstants.Errors.InvalidRequest
                    });
                }
            }

            var notification = new HandleRevocationRequestContext(Context, Scheme, Options, request, ticket);
            await Provider.HandleRevocationRequest(notification);

            if (notification.Result != null)
            {
                if (notification.Result.Handled)
                {
                    Logger.LogDebug("The revocation request was handled in user code.");

                    return true;
                }

                else if (notification.Result.Skipped)
                {
                    Logger.LogDebug("The default revocation request handling was skipped from user code.");

                    return false;
                }
            }

            else if (notification.IsRejected)
            {
                Logger.LogError("The revocation request was rejected with the following error: {Error} ; {Description}",
                                /* Error: */ notification.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
                                /* Description: */ notification.ErrorDescription);

                return await SendRevocationResponseAsync(new OpenIdConnectResponse
                {
                    Error = notification.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = notification.ErrorDescription,
                    ErrorUri = notification.ErrorUri
                });
            }

            if (!notification.Revoked)
            {
                return await SendRevocationResponseAsync(new OpenIdConnectResponse
                {
                    Error = OpenIdConnectConstants.Errors.UnsupportedTokenType,
                    ErrorDescription = "The specified token cannot be revoked."
                });
            }

            return await SendRevocationResponseAsync(new OpenIdConnectResponse());
        }

        private async Task<bool> SendRevocationResponseAsync(OpenIdConnectResponse response)
        {
            var request = Context.GetOpenIdConnectRequest();
            Context.SetOpenIdConnectResponse(response);

            response.SetProperty(OpenIdConnectConstants.Properties.MessageType,
                                 OpenIdConnectConstants.MessageTypes.RevocationResponse);

            var notification = new ApplyRevocationResponseContext(Context, Scheme, Options, request, response);
            await Provider.ApplyRevocationResponse(notification);

            if (notification.Result != null)
            {
                if (notification.Result.Handled)
                {
                    Logger.LogDebug("The revocation request was handled in user code.");

                    return true;
                }

                else if (notification.Result.Skipped)
                {
                    Logger.LogDebug("The default revocation request handling was skipped from user code.");

                    return false;
                }
            }

            Logger.LogInformation("The revocation response was successfully returned: {Response}.", response);

            return await SendPayloadAsync(response);
        }
    }
}
