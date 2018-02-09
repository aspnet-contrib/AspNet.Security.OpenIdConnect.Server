/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.Linq;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Extensions;
using AspNet.Security.OpenIdConnect.Primitives;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json.Linq;

namespace AspNet.Security.OpenIdConnect.Server
{
    public partial class OpenIdConnectServerHandler
    {
        private async Task<bool> InvokeIntrospectionEndpointAsync()
        {
            OpenIdConnectRequest request;

            // See https://tools.ietf.org/html/rfc7662#section-2.1
            // and https://tools.ietf.org/html/rfc7662#section-4
            if (HttpMethods.IsGet(Request.Method))
            {
                request = new OpenIdConnectRequest(Request.Query);
            }

            else if (HttpMethods.IsPost(Request.Method))
            {
                // See http://openid.net/specs/openid-connect-core-1_0.html#FormSerialization
                if (string.IsNullOrEmpty(Request.ContentType))
                {
                    Logger.LogError("The introspection request was rejected because " +
                                    "the mandatory 'Content-Type' header was missing.");

                    return await SendIntrospectionResponseAsync(new OpenIdConnectResponse
                    {
                        Error = OpenIdConnectConstants.Errors.InvalidRequest,
                        ErrorDescription = "The mandatory 'Content-Type' header must be specified."
                    });
                }

                // May have media/type; charset=utf-8, allow partial match.
                if (!Request.ContentType.StartsWith("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase))
                {
                    Logger.LogError("The introspection request was rejected because an invalid 'Content-Type' " +
                                    "header was specified: {ContentType}.", Request.ContentType);

                    return await SendIntrospectionResponseAsync(new OpenIdConnectResponse
                    {
                        Error = OpenIdConnectConstants.Errors.InvalidRequest,
                        ErrorDescription = "The specified 'Content-Type' header is not valid."
                    });
                }

                request = new OpenIdConnectRequest(await Request.ReadFormAsync(Context.RequestAborted));
            }

            else
            {
                Logger.LogError("The introspection request was rejected because an invalid " +
                                "HTTP method was specified: {Method}.", Request.Method);

                return await SendIntrospectionResponseAsync(new OpenIdConnectResponse
                {
                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = "The specified HTTP method is not valid."
                });
            }

            // Note: set the message type before invoking the ExtractIntrospectionRequest event.
            request.SetProperty(OpenIdConnectConstants.Properties.MessageType,
                                OpenIdConnectConstants.MessageTypes.IntrospectionRequest);

            // Store the introspection request in the ASP.NET context.
            Context.SetOpenIdConnectRequest(request);

            var @event = new ExtractIntrospectionRequestContext(Context, Scheme, Options, request);
            await Provider.ExtractIntrospectionRequest(@event);

            if (@event.Result != null)
            {
                if (@event.Result.Handled)
                {
                    Logger.LogDebug("The introspection request was handled in user code.");

                    return true;
                }

                else if (@event.Result.Skipped)
                {
                    Logger.LogDebug("The default introspection request handling was skipped from user code.");

                    return false;
                }
            }

            else if (@event.IsRejected)
            {
                Logger.LogError("The introspection request was rejected with the following error: {Error} ; {Description}",
                                /* Error: */ @event.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
                                /* Description: */ @event.ErrorDescription);

                return await SendIntrospectionResponseAsync(new OpenIdConnectResponse
                {
                    Error = @event.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = @event.ErrorDescription,
                    ErrorUri = @event.ErrorUri
                });
            }

            Logger.LogInformation("The introspection request was successfully extracted " +
                                  "from the HTTP request: {Request}.", request);

            if (string.IsNullOrEmpty(request.Token))
            {
                return await SendIntrospectionResponseAsync(new OpenIdConnectResponse
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
                    Logger.LogError("The introspection request was rejected because " +
                                    "multiple client credentials were specified.");

                    return await SendIntrospectionResponseAsync(new OpenIdConnectResponse
                    {
                        Error = OpenIdConnectConstants.Errors.InvalidRequest,
                        ErrorDescription = "Multiple client credentials cannot be specified."
                    });
                }

                request.ClientId = credentials?.Key;
                request.ClientSecret = credentials?.Value;
            }

            var context = new ValidateIntrospectionRequestContext(Context, Scheme, Options, request);
            await Provider.ValidateIntrospectionRequest(context);

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
                    Logger.LogDebug("The introspection request was handled in user code.");

                    return true;
                }

                else if (context.Result.Skipped)
                {
                    Logger.LogDebug("The default introspection request handling was skipped from user code.");

                    return false;
                }
            }

            else if (context.IsRejected)
            {
                Logger.LogError("The introspection request was rejected with the following error: {Error} ; {Description}",
                                /* Error: */ context.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
                                /* Description: */ context.ErrorDescription);

                return await SendIntrospectionResponseAsync(new OpenIdConnectResponse
                {
                    Error = context.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = context.ErrorDescription,
                    ErrorUri = context.ErrorUri
                });
            }

            // Store the validated client_id as a request property.
            request.SetProperty(OpenIdConnectConstants.Properties.ValidatedClientId, context.ClientId);

            Logger.LogInformation("The introspection request was successfully validated.");

            AuthenticationTicket ticket = null;

            // Note: use the "token_type_hint" parameter to determine
            // the type of the token sent by the client application.
            // See https://tools.ietf.org/html/rfc7662#section-2.1
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
            // See https://tools.ietf.org/html/rfc7662#section-2.1
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
                Logger.LogInformation("The introspection request was rejected because the token was invalid.");

                return await SendIntrospectionResponseAsync(new OpenIdConnectResponse
                {
                    [OpenIdConnectConstants.Parameters.Active] = false
                });
            }

            // Note: unlike refresh or identity tokens that can only be validated by client applications,
            // access tokens can be validated by either resource servers or client applications:
            // in both cases, the caller must be authenticated if the ticket is marked as confidential.
            if (context.IsSkipped && ticket.IsConfidential())
            {
                Logger.LogError("The introspection request was rejected because the caller was not authenticated.");

                return await SendIntrospectionResponseAsync(new OpenIdConnectResponse
                {
                    [OpenIdConnectConstants.Parameters.Active] = false
                });
            }

            // If the ticket is already expired, directly return active=false.
            if (ticket.Properties.ExpiresUtc.HasValue &&
                ticket.Properties.ExpiresUtc < Options.SystemClock.UtcNow)
            {
                Logger.LogInformation("The introspection request was rejected because the token was expired.");

                return await SendIntrospectionResponseAsync(new OpenIdConnectResponse
                {
                    [OpenIdConnectConstants.Parameters.Active] = false
                });
            }

            // When a client_id can be inferred from the introspection request,
            // ensure that the client application is a valid audience/presenter.
            if (!string.IsNullOrEmpty(context.ClientId))
            {
                if (ticket.IsAuthorizationCode() && ticket.HasPresenter() && !ticket.HasPresenter(context.ClientId))
                {
                    Logger.LogError("The introspection request was rejected because the " +
                                    "authorization code was issued to a different client.");

                    return await SendIntrospectionResponseAsync(new OpenIdConnectResponse
                    {
                        [OpenIdConnectConstants.Parameters.Active] = false
                    });
                }

                // Ensure the caller is listed as a valid audience or authorized presenter.
                else if (ticket.IsAccessToken() && ticket.HasAudience() && !ticket.HasAudience(context.ClientId) &&
                                                   ticket.HasPresenter() && !ticket.HasPresenter(context.ClientId))
                {
                    Logger.LogError("The introspection request was rejected because the access token " +
                                    "was issued to a different client or for another resource server.");

                    return await SendIntrospectionResponseAsync(new OpenIdConnectResponse
                    {
                        [OpenIdConnectConstants.Parameters.Active] = false
                    });
                }

                // Reject the request if the caller is not listed as a valid audience.
                else if (ticket.IsIdentityToken() && ticket.HasAudience() && !ticket.HasAudience(context.ClientId))
                {
                    Logger.LogError("The introspection request was rejected because the " +
                                    "identity token was issued to a different client.");

                    return await SendIntrospectionResponseAsync(new OpenIdConnectResponse
                    {
                        [OpenIdConnectConstants.Parameters.Active] = false
                    });
                }

                // Reject the introspection request if the caller doesn't
                // correspond to the client application the token was issued to.
                else if (ticket.IsRefreshToken() && ticket.HasPresenter() && !ticket.HasPresenter(context.ClientId))
                {
                    Logger.LogError("The introspection request was rejected because the " +
                                    "refresh token was issued to a different client.");

                    return await SendIntrospectionResponseAsync(new OpenIdConnectResponse
                    {
                        [OpenIdConnectConstants.Parameters.Active] = false
                    });
                }
            }

            var notification = new HandleIntrospectionRequestContext(Context, Scheme, Options, request, ticket)
            {
                Active = true,
                Issuer = Context.GetIssuer(Options),
                TokenId = ticket.GetTokenId(),
                TokenUsage = ticket.GetProperty(OpenIdConnectConstants.Properties.TokenUsage),
                Subject = ticket.Principal.GetClaim(OpenIdConnectConstants.Claims.Subject)
            };

            // Note: only set "token_type" when the received token is an access token.
            // See https://tools.ietf.org/html/rfc7662#section-2.2
            // and https://tools.ietf.org/html/rfc6749#section-5.1
            if (ticket.IsAccessToken())
            {
                notification.TokenType = OpenIdConnectConstants.TokenTypes.Bearer;
            }

            notification.IssuedAt = ticket.Properties.IssuedUtc;
            notification.NotBefore = ticket.Properties.IssuedUtc;
            notification.ExpiresAt = ticket.Properties.ExpiresUtc;

            // Infer the audiences/client_id claims from the properties stored in the authentication ticket.
            // Note: the client_id claim must be a unique string so multiple presenters cannot be returned.
            // To work around this limitation, only the first one is returned if multiple values are listed.
            notification.Audiences.UnionWith(ticket.GetAudiences());
            notification.ClientId = ticket.GetPresenters().FirstOrDefault();

            // Note: non-metadata claims are only added if the caller's client_id is known
            // AND is in the specified audiences, unless there's no explicit audience.
            if (!ticket.HasAudience() || (!string.IsNullOrEmpty(context.ClientId) && ticket.HasAudience(context.ClientId)))
            {
                notification.Username = ticket.Principal.Identity?.Name;
                notification.Scopes.UnionWith(ticket.GetScopes());

                // Potentially sensitive claims are only exposed if the client was authenticated
                // and if the authentication ticket corresponds to an identity or access token.
                if (context.IsValidated && (ticket.IsAccessToken() || ticket.IsIdentityToken()))
                {
                    foreach (var grouping in ticket.Principal.Claims.GroupBy(claim => claim.Type))
                    {
                        // Exclude standard claims, that are already handled via strongly-typed properties.
                        // Make sure to always update this list when adding new built-in claim properties.
                        var type = grouping.Key;
                        switch (type)
                        {
                            case OpenIdConnectConstants.Claims.Audience:
                            case OpenIdConnectConstants.Claims.ExpiresAt:
                            case OpenIdConnectConstants.Claims.IssuedAt:
                            case OpenIdConnectConstants.Claims.Issuer:
                            case OpenIdConnectConstants.Claims.NotBefore:
                            case OpenIdConnectConstants.Claims.Scope:
                            case OpenIdConnectConstants.Claims.Subject:
                            case OpenIdConnectConstants.Claims.TokenType:
                            case OpenIdConnectConstants.Claims.TokenUsage:
                                continue;
                        }

                        var claims = grouping.ToArray();
                        switch (claims.Length)
                        {
                            case 0: continue;

                            // When there's only one claim with the same type, directly
                            // convert the claim as an OpenIdConnectParameter instance,
                            // whose token type is determined from the claim value type.
                            case 1:
                            {
                                notification.Claims[type] = claims[0].AsParameter();

                                continue;
                            }

                            // When multiple claims share the same type, convert all the claims
                            // to OpenIdConnectParameter instances, retrieve the underlying
                            // JSON values and add everything to a new JSON array.
                            default:
                            {
                                notification.Claims[type] = new JArray(claims.Select(claim => claim.AsParameter().Value));

                                continue;
                            }
                        }
                    }
                }
            }

            await Provider.HandleIntrospectionRequest(notification);

            if (notification.Result != null)
            {
                if (notification.Result.Handled)
                {
                    Logger.LogDebug("The introspection request was handled in user code.");

                    return true;
                }

                else if (notification.Result.Skipped)
                {
                    Logger.LogDebug("The default introspection request handling was skipped from user code.");

                    return false;
                }
            }

            else if (notification.IsRejected)
            {
                Logger.LogError("The introspection request was rejected with the following error: {Error} ; {Description}",
                                /* Error: */ notification.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
                                /* Description: */ notification.ErrorDescription);

                return await SendIntrospectionResponseAsync(new OpenIdConnectResponse
                {
                    Error = notification.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = notification.ErrorDescription,
                    ErrorUri = notification.ErrorUri
                });
            }

            var response = new OpenIdConnectResponse
            {
                [OpenIdConnectConstants.Claims.Active] = notification.Active
            };

            // Only add the other properties if
            // the token is considered as active.
            if (notification.Active)
            {
                response[OpenIdConnectConstants.Claims.Issuer] = notification.Issuer;
                response[OpenIdConnectConstants.Claims.Username] = notification.Username;
                response[OpenIdConnectConstants.Claims.Subject] = notification.Subject;
                response[OpenIdConnectConstants.Claims.Scope] = string.Join(" ", notification.Scopes);
                response[OpenIdConnectConstants.Claims.JwtId] = notification.TokenId;
                response[OpenIdConnectConstants.Claims.TokenType] = notification.TokenType;
                response[OpenIdConnectConstants.Claims.TokenUsage] = notification.TokenUsage;
                response[OpenIdConnectConstants.Claims.ClientId] = notification.ClientId;

                if (notification.IssuedAt != null)
                {
                    response[OpenIdConnectConstants.Claims.IssuedAt] =
                        EpochTime.GetIntDate(notification.IssuedAt.Value.UtcDateTime);
                }

                if (notification.NotBefore != null)
                {
                    response[OpenIdConnectConstants.Claims.NotBefore] =
                        EpochTime.GetIntDate(notification.NotBefore.Value.UtcDateTime);
                }

                if (notification.ExpiresAt != null)
                {
                    response[OpenIdConnectConstants.Claims.ExpiresAt] =
                        EpochTime.GetIntDate(notification.ExpiresAt.Value.UtcDateTime);
                }

                switch (notification.Audiences.Count)
                {
                    case 0: break;

                    case 1:
                        response[OpenIdConnectConstants.Claims.Audience] = notification.Audiences.ElementAt(0);
                        break;

                    default:
                        response[OpenIdConnectConstants.Claims.Audience] = new JArray(notification.Audiences);
                        break;
                }

                foreach (var claim in notification.Claims)
                {
                    response.SetParameter(claim.Key, claim.Value);
                }
            }

            return await SendIntrospectionResponseAsync(response);
        }

        private async Task<bool> SendIntrospectionResponseAsync(OpenIdConnectResponse response)
        {
            var request = Context.GetOpenIdConnectRequest();
            Context.SetOpenIdConnectResponse(response);

            response.SetProperty(OpenIdConnectConstants.Properties.MessageType,
                                 OpenIdConnectConstants.MessageTypes.IntrospectionResponse);

            var notification = new ApplyIntrospectionResponseContext(Context, Scheme, Options, request, response);
            await Provider.ApplyIntrospectionResponse(notification);

            if (notification.Result != null)
            {
                if (notification.Result.Handled)
                {
                    Logger.LogDebug("The introspection request was handled in user code.");

                    return true;
                }

                else if (notification.Result.Skipped)
                {
                    Logger.LogDebug("The default introspection request handling was skipped from user code.");

                    return false;
                }
            }

            Logger.LogInformation("The introspection response was successfully returned: {Response}.", response);

            return await SendPayloadAsync(response);
        }
    }
}
