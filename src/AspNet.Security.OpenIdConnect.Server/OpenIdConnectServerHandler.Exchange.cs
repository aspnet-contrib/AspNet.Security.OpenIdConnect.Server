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
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Net.Http.Headers;

namespace AspNet.Security.OpenIdConnect.Server
{
    internal partial class OpenIdConnectServerHandler : AuthenticationHandler<OpenIdConnectServerOptions>
    {
        private async Task<bool> InvokeTokenEndpointAsync()
        {
            if (!string.Equals(Request.Method, "POST", StringComparison.OrdinalIgnoreCase))
            {
                Logger.LogError("The token request was rejected because an invalid " +
                                "HTTP method was received: {Method}.", Request.Method);

                return await SendTokenResponseAsync(new OpenIdConnectResponse
                {
                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = "A malformed token request has been received: make sure to use POST."
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
                    ErrorDescription = "A malformed token request has been received: " +
                        "the mandatory 'Content-Type' header was missing from the POST request."
                });
            }

            // May have media/type; charset=utf-8, allow partial match.
            if (!Request.ContentType.StartsWith("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase))
            {
                Logger.LogError("The token request was rejected because an invalid 'Content-Type' " +
                                "header was received: {ContentType}.", Request.ContentType);

                return await SendTokenResponseAsync(new OpenIdConnectResponse
                {
                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = "A malformed token request has been received: " +
                        "the 'Content-Type' header contained an unexcepted value. " +
                        "Make sure to use 'application/x-www-form-urlencoded'."
                });
            }

            var request = new OpenIdConnectRequest(await Request.ReadFormAsync(Context.RequestAborted));

            // Note: set the message type before invoking the ExtractTokenRequest event.
            request.SetProperty(OpenIdConnectConstants.Properties.MessageType,
                                OpenIdConnectConstants.MessageTypes.TokenRequest);

            // Store the token request in the ASP.NET context.
            Context.SetOpenIdConnectRequest(request);

            var @event = new ExtractTokenRequestContext(Context, Options, request);
            await Options.Provider.ExtractTokenRequest(@event);

            if (@event.HandledResponse)
            {
                Logger.LogDebug("The token request was handled in user code.");

                return true;
            }

            else if (@event.Skipped)
            {
                Logger.LogDebug("The default token request handling was skipped from user code.");

                return false;
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
                                  "from the HTTP request: {Request}", request);

            // Reject token requests missing the mandatory grant_type parameter.
            if (string.IsNullOrEmpty(request.GrantType))
            {
                Logger.LogError("The token request was rejected because the grant type was missing.");

                return await SendTokenResponseAsync(new OpenIdConnectResponse
                {
                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = "The mandatory 'grant_type' parameter was missing.",
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
                    ErrorDescription = "The mandatory 'code' parameter was missing."
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
                    ErrorDescription = "The mandatory 'refresh_token' parameter was missing."
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
                    ErrorDescription = "The mandatory 'username' and/or 'password' parameters " +
                                       "was/were missing from the request message."
                });
            }

            // When client_id and client_secret are both null, try to extract them from the Authorization header.
            // See http://tools.ietf.org/html/rfc6749#section-2.3.1 and
            // http://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication
            if (string.IsNullOrEmpty(request.ClientId) && string.IsNullOrEmpty(request.ClientSecret))
            {
                string header = Request.Headers[HeaderNames.Authorization];
                if (!string.IsNullOrEmpty(header) && header.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
                {
                    try
                    {
                        var value = header.Substring("Basic ".Length).Trim();
                        var data = Encoding.UTF8.GetString(Convert.FromBase64String(value));

                        var index = data.IndexOf(':');
                        if (index >= 0)
                        {
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

            // If the validation context was set as fully validated,
            // mark the OpenID Connect request as confidential.
            if (context.IsValidated)
            {
                request.SetProperty(OpenIdConnectConstants.Properties.ConfidentialityLevel,
                                    OpenIdConnectConstants.ConfidentialityLevels.Private);
            }

            if (context.HandledResponse)
            {
                Logger.LogDebug("The token request was handled in user code.");

                return true;
            }

            else if (context.Skipped)
            {
                Logger.LogDebug("The default token request handling was skipped from user code.");

                return false;
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
                    ErrorDescription = "Client authentication is required when using client_credentials."
                });
            }

            // Ensure that the client_id has been set from the ValidateTokenRequest event.
            else if (context.IsValidated && string.IsNullOrEmpty(request.ClientId))
            {
                Logger.LogError("The token request was validated but the client_id was not set.");

                return await SendTokenResponseAsync(new OpenIdConnectResponse
                {
                    Error = OpenIdConnectConstants.Errors.ServerError,
                    ErrorDescription = "An internal server error occurred."
                });
            }

            // At this stage, client_id cannot be null for grant_type=authorization_code requests,
            // as it must either be set in the ValidateTokenRequest notification
            // by the developer or manually flowed by non-confidential client applications.
            // See https://tools.ietf.org/html/rfc6749#section-4.1.3
            if (request.IsAuthorizationCodeGrantType() && string.IsNullOrEmpty(request.ClientId))
            {
                Logger.LogError("The token request was rejected because the mandatory 'client_id' was missing.");

                return await SendTokenResponseAsync(new OpenIdConnectResponse
                {
                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = "client_id was missing from the token request"
                });
            }

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
                        ErrorDescription = "Invalid ticket"
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
                        ErrorDescription = "Client authentication is required to use this ticket"
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
                        ErrorDescription = "Expired ticket"
                    });
                }

                // Note: presenters may be empty during a grant_type=refresh_token request if the refresh token
                // was issued to a public client but cannot be null for an authorization code grant request.
                var presenters = ticket.GetPresenters();
                if (request.IsAuthorizationCodeGrantType() && !presenters.Any())
                {
                    Logger.LogError("The token request was rejected because the authorization " +
                                    "code didn't contain any valid presenter.");

                    return await SendTokenResponseAsync(new OpenIdConnectResponse
                    {
                        Error = OpenIdConnectConstants.Errors.ServerError,
                        ErrorDescription = "An internal server error occurred."
                    });
                }

                // Ensure the authorization code/refresh token was issued to the client application making the token request.
                // Note: when using the refresh token grant, client_id is optional but must validated if present.
                // As a consequence, this check doesn't depend on the actual status of client authentication.
                // See https://tools.ietf.org/html/rfc6749#section-6
                // and http://openid.net/specs/openid-connect-core-1_0.html#RefreshingAccessToken
                if (!string.IsNullOrEmpty(request.ClientId) && presenters.Any() &&
                    !presenters.Contains(request.ClientId, StringComparer.Ordinal))
                {
                    Logger.LogError("The token request was rejected because the authorization " +
                                    "code was issued to a different client application.");

                    return await SendTokenResponseAsync(new OpenIdConnectResponse
                    {
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
                if (request.IsAuthorizationCodeGrantType() && !string.IsNullOrEmpty(address))
                {
                    ticket.RemoveProperty(OpenIdConnectConstants.Properties.RedirectUri);

                    if (string.IsNullOrEmpty(request.RedirectUri))
                    {
                        Logger.LogError("The token request was rejected because the mandatory 'redirect_uri' " +
                                        "parameter was missing from the grant_type=authorization_code request.");

                        return await SendTokenResponseAsync(new OpenIdConnectResponse
                        {
                            Error = OpenIdConnectConstants.Errors.InvalidRequest,
                            ErrorDescription = "redirect_uri was missing from the token request"
                        });
                    }

                    else if (!string.Equals(address, request.RedirectUri, StringComparison.Ordinal))
                    {
                        Logger.LogError("The token request was rejected because the 'redirect_uri' " +
                                        "parameter didn't correspond to the expected value.");

                        return await SendTokenResponseAsync(new OpenIdConnectResponse
                        {
                            Error = OpenIdConnectConstants.Errors.InvalidGrant,
                            ErrorDescription = "Authorization code does not contain matching redirect_uri"
                        });
                    }
                }

                // If a code challenge was initially sent in the authorization request and associated with the
                // code, validate the code verifier to ensure the token request is sent by a legit caller.
                var challenge = ticket.GetProperty(OpenIdConnectConstants.Properties.CodeChallenge);
                if (request.IsAuthorizationCodeGrantType() && !string.IsNullOrEmpty(challenge))
                {
                    ticket.RemoveProperty(OpenIdConnectConstants.Properties.CodeChallenge);

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
                            ErrorDescription = "The required 'code_verifier' was missing from the token request."
                        });
                    }

                    // Note: the code challenge method is always validated when receiving the authorization request.
                    var method = ticket.GetProperty(OpenIdConnectConstants.Properties.CodeChallengeMethod);
                    ticket.RemoveProperty(OpenIdConnectConstants.Properties.CodeChallengeMethod);

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
                            ErrorDescription = "The specified 'code_verifier' was invalid."
                        });
                    }
                }

                if (request.IsRefreshTokenGrantType() && !string.IsNullOrEmpty(request.Resource))
                {
                    // When an explicit resource parameter has been included in the token request
                    // but was missing from the initial request, the request MUST be rejected.
                    var resources = ticket.GetResources();
                    if (!resources.Any())
                    {
                        Logger.LogError("The token request was rejected because the 'resource' parameter was not allowed.");

                        return await SendTokenResponseAsync(new OpenIdConnectResponse
                        {
                            Error = OpenIdConnectConstants.Errors.InvalidGrant,
                            ErrorDescription = "Token request cannot contain a resource parameter " +
                                               "if the authorization request didn't contain one"
                        });
                    }

                    // When an explicit resource parameter has been included in the token request,
                    // the authorization server MUST ensure that it doesn't contain resources
                    // that were not allowed during the initial authorization/token request.
                    else if (!new HashSet<string>(resources).IsSupersetOf(request.GetResources()))
                    {
                        Logger.LogError("The token request was rejected because the 'resource' parameter was not valid.");

                        return await SendTokenResponseAsync(new OpenIdConnectResponse
                        {
                            Error = OpenIdConnectConstants.Errors.InvalidGrant,
                            ErrorDescription = "Token request doesn't contain a valid resource parameter"
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
                            ErrorDescription = "Token request cannot contain a scope parameter " +
                                               "if the authorization request didn't contain one"
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
                            ErrorDescription = "Token request doesn't contain a valid scope parameter"
                        });
                    }
                }
            }

            var notification = new HandleTokenRequestContext(Context, Options, request, ticket);
            await Options.Provider.HandleTokenRequest(notification);

            if (notification.HandledResponse)
            {
                Logger.LogDebug("The token request was handled in user code.");

                return true;
            }

            else if (notification.Skipped)
            {
                Logger.LogDebug("The default token request handling was skipped from user code.");

                return false;
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
            // an error code indicating that the grant type is not supported.
            if (ticket == null)
            {
                Logger.LogError("The token request was rejected because no authentication " +
                                "ticket was returned by application code.");

                return await SendTokenResponseAsync(new OpenIdConnectResponse
                {
                    Error = OpenIdConnectConstants.Errors.UnsupportedGrantType,
                    ErrorDescription = "The specified grant_type parameter is not supported."
                });
            }

            // Call HandleSignInAsync to generate a token response.
            return await HandleSignInAsync(ticket);
        }

        private async Task<bool> SendTokenResponseAsync(OpenIdConnectResponse response, AuthenticationTicket ticket = null)
        {
            var request = Context.GetOpenIdConnectRequest();
            Context.SetOpenIdConnectResponse(response);

            response.SetProperty(OpenIdConnectConstants.Properties.MessageType,
                                 OpenIdConnectConstants.MessageTypes.TokenResponse);

            var notification = new ApplyTokenResponseContext(Context, Options, ticket, request, response);
            await Options.Provider.ApplyTokenResponse(notification);

            if (notification.HandledResponse)
            {
                Logger.LogDebug("The token request was handled in user code.");

                return true;
            }

            else if (notification.Skipped)
            {
                Logger.LogDebug("The default token request handling was skipped from user code.");

                return false;
            }

            Logger.LogInformation("The token response was successfully returned: {Response}", response);

            return await SendPayloadAsync(response);
        }
    }
}
