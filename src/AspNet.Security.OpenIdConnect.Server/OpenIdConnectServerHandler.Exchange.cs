/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Extensions;
using AspNet.Security.OpenIdConnect.Primitives;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;

namespace AspNet.Security.OpenIdConnect.Server
{
    public partial class OpenIdConnectServerHandler
    {
        private async Task<bool> InvokeTokenEndpointAsync()
        {
            if (!HttpMethods.IsPost(Request.Method))
            {
                Logger.LogError("The token request was rejected because an invalid " +
                                "HTTP method was specified: {Method}.", Request.Method);

                return await SendTokenResponseAsync(new OpenIdConnectResponse
                {
                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = "The specified HTTP method is not valid."
                });
            }

            // See http://openid.net/specs/openid-connect-core-1_0.html#FormSerialization
            if (string.IsNullOrEmpty(Request.ContentType))
            {
                Logger.LogError("The token request was rejected because the " +
                                "mandatory 'Content-Type' header was missing.");

                return await SendTokenResponseAsync(new OpenIdConnectResponse
                {
                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = "The mandatory 'Content-Type' header must be specified."
                });
            }

            // May have media/type; charset=utf-8, allow partial match.
            if (!Request.ContentType.StartsWith("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase))
            {
                Logger.LogError("The token request was rejected because an invalid 'Content-Type' " +
                                "header was specified: {ContentType}.", Request.ContentType);

                return await SendTokenResponseAsync(new OpenIdConnectResponse
                {
                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = "The specified 'Content-Type' header is not valid."
                });
            }

            var request = new OpenIdConnectRequest(await Request.ReadFormAsync(Context.RequestAborted));

            // Note: set the message type before invoking the ExtractTokenRequest event.
            request.SetProperty(OpenIdConnectConstants.Properties.MessageType,
                                OpenIdConnectConstants.MessageTypes.TokenRequest);

            // Store the token request in the ASP.NET context.
            Context.SetOpenIdConnectRequest(request);

            var @event = new ExtractTokenRequestContext(Context, Scheme, Options, request);
            await Provider.ExtractTokenRequest(@event);

            if (@event.Result != null)
            {
                if (@event.Result.Handled)
                {
                    Logger.LogDebug("The token request was handled in user code.");

                    return true;
                }

                else if (@event.Result.Skipped)
                {
                    Logger.LogDebug("The default token request handling was skipped from user code.");

                    return false;
                }
            }

            else if (@event.IsRejected)
            {
                Logger.LogError("The token request was rejected with the following error: {Error} ; {Description}",
                                /* Error: */ @event.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
                                /* Description: */ @event.ErrorDescription);

                return await SendTokenResponseAsync(new OpenIdConnectResponse
                {
                    Error = @event.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = @event.ErrorDescription,
                    ErrorUri = @event.ErrorUri
                });
            }

            Logger.LogInformation("The token request was successfully extracted " +
                                  "from the HTTP request: {Request}.", request);

            // Reject token requests missing the mandatory grant_type parameter.
            if (string.IsNullOrEmpty(request.GrantType))
            {
                Logger.LogError("The token request was rejected because the grant type was missing.");

                return await SendTokenResponseAsync(new OpenIdConnectResponse
                {
                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = "The mandatory 'grant_type' parameter is missing.",
                });
            }

            // Reject grant_type=authorization_code requests if the authorization endpoint is disabled.
            else if (request.IsAuthorizationCodeGrantType() && !Options.AuthorizationEndpointPath.HasValue)
            {
                Logger.LogError("The token request was rejected because the authorization code grant was disabled.");

                return await SendTokenResponseAsync(new OpenIdConnectResponse
                {
                    Error = OpenIdConnectConstants.Errors.UnsupportedGrantType,
                    ErrorDescription = "The authorization code grant is not allowed by this authorization server."
                });
            }

            // Reject grant_type=authorization_code requests missing the authorization code.
            // See https://tools.ietf.org/html/rfc6749#section-4.1.3
            else if (request.IsAuthorizationCodeGrantType() && string.IsNullOrEmpty(request.Code))
            {
                Logger.LogError("The token request was rejected because the authorization code was missing.");

                return await SendTokenResponseAsync(new OpenIdConnectResponse
                {
                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = "The mandatory 'code' parameter is missing."
                });
            }

            // Reject grant_type=refresh_token requests missing the refresh token.
            // See https://tools.ietf.org/html/rfc6749#section-6
            else if (request.IsRefreshTokenGrantType() && string.IsNullOrEmpty(request.RefreshToken))
            {
                Logger.LogError("The token request was rejected because the refresh token was missing.");

                return await SendTokenResponseAsync(new OpenIdConnectResponse
                {
                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = "The mandatory 'refresh_token' parameter is missing."
                });
            }

            // Reject grant_type=password requests missing username or password.
            // See https://tools.ietf.org/html/rfc6749#section-4.3.2
            else if (request.IsPasswordGrantType() && (string.IsNullOrEmpty(request.Username) ||
                                                       string.IsNullOrEmpty(request.Password)))
            {
                Logger.LogError("The token request was rejected because the resource owner credentials were missing.");

                return await SendTokenResponseAsync(new OpenIdConnectResponse
                {
                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = "The mandatory 'username' and/or 'password' parameters are missing."
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
                    Logger.LogError("The token request was rejected because multiple client credentials were specified.");

                    return await SendTokenResponseAsync(new OpenIdConnectResponse
                    {
                        Error = OpenIdConnectConstants.Errors.InvalidRequest,
                        ErrorDescription = "Multiple client credentials cannot be specified."
                    });
                }

                request.ClientId = credentials?.Key;
                request.ClientSecret = credentials?.Value;
            }

            var context = new ValidateTokenRequestContext(Context, Scheme, Options, request);
            await Provider.ValidateTokenRequest(context);

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
                    Logger.LogDebug("The token request was handled in user code.");

                    return true;
                }

                else if (context.Result.Skipped)
                {
                    Logger.LogDebug("The default token request handling was skipped from user code.");

                    return false;
                }
            }

            else if (context.IsRejected)
            {
                Logger.LogError("The token request was rejected with the following error: {Error} ; {Description}",
                                /* Error: */ context.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
                                /* Description: */ context.ErrorDescription);

                return await SendTokenResponseAsync(new OpenIdConnectResponse
                {
                    Error = context.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = context.ErrorDescription,
                    ErrorUri = context.ErrorUri
                });
            }

            // Reject grant_type=client_credentials requests if validation was skipped.
            else if (context.IsSkipped && request.IsClientCredentialsGrantType())
            {
                Logger.LogError("The token request must be fully validated to use the client_credentials grant type.");

                return await SendTokenResponseAsync(new OpenIdConnectResponse
                {
                    Error = OpenIdConnectConstants.Errors.InvalidGrant,
                    ErrorDescription = "Client authentication is required when using the client credentials grant."
                });
            }

            // At this stage, client_id cannot be null for grant_type=authorization_code requests,
            // as it must either be set in the ValidateTokenRequest notification
            // by the developer or manually flowed by non-confidential client applications.
            // See https://tools.ietf.org/html/rfc6749#section-4.1.3
            if (request.IsAuthorizationCodeGrantType() && string.IsNullOrEmpty(context.ClientId))
            {
                Logger.LogError("The token request was rejected because the mandatory 'client_id' was missing.");

                return await SendTokenResponseAsync(new OpenIdConnectResponse
                {
                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = "The mandatory 'client_id' parameter is missing."
                });
            }

            // Store the validated client_id as a request property.
            request.SetProperty(OpenIdConnectConstants.Properties.ValidatedClientId, context.ClientId);

            Logger.LogInformation("The token request was successfully validated.");

            AuthenticationTicket ticket = null;

            // See http://tools.ietf.org/html/rfc6749#section-4.1
            // and http://tools.ietf.org/html/rfc6749#section-4.1.3 (authorization code grant).
            // See http://tools.ietf.org/html/rfc6749#section-6 (refresh token grant).
            if (request.IsAuthorizationCodeGrantType() || request.IsRefreshTokenGrantType())
            {
                ticket = request.IsAuthorizationCodeGrantType() ?
                    await DeserializeAuthorizationCodeAsync(request.Code, request) :
                    await DeserializeRefreshTokenAsync(request.RefreshToken, request);

                if (ticket == null)
                {
                    Logger.LogError("The token request was rejected because the " +
                                    "authorization code or the refresh token was invalid.");

                    return await SendTokenResponseAsync(new OpenIdConnectResponse
                    {
                        Error = OpenIdConnectConstants.Errors.InvalidGrant,
                        ErrorDescription = request.IsAuthorizationCodeGrantType() ?
                            "The specified authorization code is invalid." :
                            "The specified refresh token is invalid."
                    });
                }

                // If the client was fully authenticated when retrieving its refresh token,
                // the current request must be rejected if client authentication was not enforced.
                if (request.IsRefreshTokenGrantType() && !context.IsValidated && ticket.IsConfidential())
                {
                    Logger.LogError("The token request was rejected because client authentication " +
                                    "was required to use the confidential refresh token.");

                    return await SendTokenResponseAsync(new OpenIdConnectResponse
                    {
                        Error = OpenIdConnectConstants.Errors.InvalidGrant,
                        ErrorDescription = "Client authentication is required to use the specified refresh token."
                    });
                }

                if (ticket.Properties.ExpiresUtc.HasValue &&
                    ticket.Properties.ExpiresUtc < Options.SystemClock.UtcNow)
                {
                    Logger.LogError("The token request was rejected because the " +
                                    "authorization code or the refresh token was expired.");

                    return await SendTokenResponseAsync(new OpenIdConnectResponse
                    {
                        Error = OpenIdConnectConstants.Errors.InvalidGrant,
                        ErrorDescription = request.IsAuthorizationCodeGrantType() ?
                            "The specified authorization code is no longer valid." :
                            "The specified refresh token is no longer valid."
                    });
                }

                // Note: presenters may be empty during a grant_type=refresh_token request if the refresh token
                // was issued to a public client but cannot be null for an authorization code grant request.
                var presenters = ticket.GetPresenters();
                if (request.IsAuthorizationCodeGrantType() && !presenters.Any())
                {
                    throw new InvalidOperationException("The presenters list cannot be extracted from the authorization code.");
                }

                // Ensure the authorization code/refresh token was issued to the client application making the token request.
                // Note: when using the refresh token grant, client_id is optional but must validated if present.
                // As a consequence, this check doesn't depend on the actual status of client authentication.
                // See https://tools.ietf.org/html/rfc6749#section-6
                // and http://openid.net/specs/openid-connect-core-1_0.html#RefreshingAccessToken
                if (!string.IsNullOrEmpty(context.ClientId) && presenters.Any() &&
                    !presenters.Contains(context.ClientId, StringComparer.Ordinal))
                {
                    Logger.LogError("The token request was rejected because the authorization " +
                                    "code was issued to a different client application.");

                    return await SendTokenResponseAsync(new OpenIdConnectResponse
                    {
                        Error = OpenIdConnectConstants.Errors.InvalidGrant,
                        ErrorDescription = request.IsAuthorizationCodeGrantType() ?
                            "The specified authorization code cannot be used by this client application." :
                            "The specified refresh token cannot be used by this client application."
                    });
                }

                // Validate the redirect_uri flowed by the client application during this token request.
                // Note: for pure OAuth2 requests, redirect_uri is only mandatory if the authorization request
                // contained an explicit redirect_uri. OpenID Connect requests MUST include a redirect_uri
                // but the specifications allow proceeding the token request without returning an error
                // if the authorization request didn't contain an explicit redirect_uri.
                // See https://tools.ietf.org/html/rfc6749#section-4.1.3
                // and http://openid.net/specs/openid-connect-core-1_0.html#TokenRequestValidation
                var address = ticket.GetProperty(OpenIdConnectConstants.Properties.OriginalRedirectUri);
                if (request.IsAuthorizationCodeGrantType() && !string.IsNullOrEmpty(address))
                {
                    if (string.IsNullOrEmpty(request.RedirectUri))
                    {
                        Logger.LogError("The token request was rejected because the mandatory 'redirect_uri' " +
                                        "parameter was missing from the grant_type=authorization_code request.");

                        return await SendTokenResponseAsync(new OpenIdConnectResponse
                        {
                            Error = OpenIdConnectConstants.Errors.InvalidRequest,
                            ErrorDescription = "The mandatory 'redirect_uri' parameter is missing."
                        });
                    }

                    else if (!string.Equals(address, request.RedirectUri, StringComparison.Ordinal))
                    {
                        Logger.LogError("The token request was rejected because the 'redirect_uri' " +
                                        "parameter didn't correspond to the expected value.");

                        return await SendTokenResponseAsync(new OpenIdConnectResponse
                        {
                            Error = OpenIdConnectConstants.Errors.InvalidGrant,
                            ErrorDescription = "The specified 'redirect_uri' parameter doesn't match the client " +
                                               "redirection endpoint the authorization code was initially sent to."
                        });
                    }
                }

                // If a code challenge was initially sent in the authorization request and associated with the
                // code, validate the code verifier to ensure the token request is sent by a legit caller.
                var challenge = ticket.GetProperty(OpenIdConnectConstants.Properties.CodeChallenge);
                if (request.IsAuthorizationCodeGrantType() && !string.IsNullOrEmpty(challenge))
                {
                    // Get the code verifier from the token request.
                    // If it cannot be found, return an invalid_grant error.
                    var verifier = request.CodeVerifier;
                    if (string.IsNullOrEmpty(verifier))
                    {
                        Logger.LogError("The token request was rejected because the required 'code_verifier' " +
                                        "parameter was missing from the grant_type=authorization_code request.");

                        return await SendTokenResponseAsync(new OpenIdConnectResponse
                        {
                            Error = OpenIdConnectConstants.Errors.InvalidRequest,
                            ErrorDescription = "The mandatory 'code_verifier' parameter is missing."
                        });
                    }

                    // Note: the code challenge method is always validated when receiving the authorization request.
                    var method = ticket.GetProperty(OpenIdConnectConstants.Properties.CodeChallengeMethod);

                    Debug.Assert(string.IsNullOrEmpty(method) ||
                                 string.Equals(method, OpenIdConnectConstants.CodeChallengeMethods.Plain, StringComparison.Ordinal) ||
                                 string.Equals(method, OpenIdConnectConstants.CodeChallengeMethods.Sha256, StringComparison.Ordinal),
                        "The specified code challenge method should be supported.");

                    // If the S256 challenge method was used, compute the hash corresponding to the code verifier.
                    if (string.Equals(method, OpenIdConnectConstants.CodeChallengeMethods.Sha256, StringComparison.Ordinal))
                    {
                        using (var algorithm = SHA256.Create())
                        {
                            // Compute the SHA-256 hash of the code verifier and encode it using base64-url.
                            // See https://tools.ietf.org/html/rfc7636#section-4.6 for more information.
                            var hash = algorithm.ComputeHash(Encoding.ASCII.GetBytes(request.CodeVerifier));

                            verifier = Base64UrlEncoder.Encode(hash);
                        }
                    }

                    // Compare the verifier and the code challenge: if the two don't match, return an error.
                    // Note: to prevent timing attacks, a time-constant comparer is always used.
                    if (!OpenIdConnectServerHelpers.AreEqual(verifier, challenge))
                    {
                        Logger.LogError("The token request was rejected because the 'code_verifier' was invalid.");

                        return await SendTokenResponseAsync(new OpenIdConnectResponse
                        {
                            Error = OpenIdConnectConstants.Errors.InvalidGrant,
                            ErrorDescription = "The specified 'code_verifier' parameter is invalid."
                        });
                    }
                }

                if (request.IsRefreshTokenGrantType() && !string.IsNullOrEmpty(request.Scope))
                {
                    // When an explicit scope parameter has been included in the token request
                    // but was missing from the initial request, the request MUST be rejected.
                    // See http://tools.ietf.org/html/rfc6749#section-6
                    var scopes = ticket.GetScopes();
                    if (!scopes.Any())
                    {
                        Logger.LogError("The token request was rejected because the 'scope' parameter was not allowed.");

                        return await SendTokenResponseAsync(new OpenIdConnectResponse
                        {
                            Error = OpenIdConnectConstants.Errors.InvalidGrant,
                            ErrorDescription = "The 'scope' parameter is not valid in this context."
                        });
                    }

                    // When an explicit scope parameter has been included in the token request,
                    // the authorization server MUST ensure that it doesn't contain scopes
                    // that were not allowed during the initial authorization/token request.
                    // See https://tools.ietf.org/html/rfc6749#section-6
                    else if (!new HashSet<string>(scopes).IsSupersetOf(request.GetScopes()))
                    {
                        Logger.LogError("The token request was rejected because the 'scope' parameter was not valid.");

                        return await SendTokenResponseAsync(new OpenIdConnectResponse
                        {
                            Error = OpenIdConnectConstants.Errors.InvalidGrant,
                            ErrorDescription = "The specified 'scope' parameter is invalid."
                        });
                    }
                }
            }

            var notification = new HandleTokenRequestContext(Context, Scheme, Options, request, ticket);
            await Provider.HandleTokenRequest(notification);

            if (notification.Result != null)
            {
                if (notification.Result.Handled)
                {
                    Logger.LogDebug("The token request was handled in user code.");

                    return true;
                }

                else if (notification.Result.Skipped)
                {
                    Logger.LogDebug("The default token request handling was skipped from user code.");

                    return false;
                }
            }

            else if (notification.IsRejected)
            {
                Logger.LogError("The token request was rejected with the following error: {Error} ; {Description}",
                                /* Error: */ notification.Error ?? OpenIdConnectConstants.Errors.InvalidGrant,
                                /* Description: */ notification.ErrorDescription);

                return await SendTokenResponseAsync(new OpenIdConnectResponse
                {
                    Error = notification.Error ?? OpenIdConnectConstants.Errors.InvalidGrant,
                    ErrorDescription = notification.ErrorDescription,
                    ErrorUri = notification.ErrorUri
                });
            }

            // Flow the changes made to the ticket.
            ticket = notification.Ticket;

            // Ensure an authentication ticket has been provided or return
            // an error code indicating that the request was rejected.
            if (ticket == null)
            {
                Logger.LogError("The token request was rejected because it was not handled by the user code.");

                return await SendTokenResponseAsync(new OpenIdConnectResponse
                {
                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = "The token request was rejected by the authorization server."
                });
            }

            return await SignInAsync(ticket);
        }

        private async Task<bool> SendTokenResponseAsync(OpenIdConnectResponse response, AuthenticationTicket ticket = null)
        {
            var request = Context.GetOpenIdConnectRequest();
            Context.SetOpenIdConnectResponse(response);

            response.SetProperty(OpenIdConnectConstants.Properties.MessageType,
                                 OpenIdConnectConstants.MessageTypes.TokenResponse);

            var notification = new ApplyTokenResponseContext(Context, Scheme, Options, ticket, request, response);
            await Provider.ApplyTokenResponse(notification);

            if (notification.Result != null)
            {
                if (notification.Result.Handled)
                {
                    Logger.LogDebug("The token request was handled in user code.");

                    return true;
                }

                else if (notification.Result.Skipped)
                {
                    Logger.LogDebug("The default token request handling was skipped from user code.");

                    return false;
                }
            }

            Logger.LogInformation("The token response was successfully returned: {Response}.", response);

            return await SendPayloadAsync(response);
        }
    }
}
