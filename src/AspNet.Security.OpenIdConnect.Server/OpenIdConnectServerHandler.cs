/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Extensions;
using AspNet.Security.OpenIdConnect.Primitives;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using Microsoft.Net.Http.Headers;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace AspNet.Security.OpenIdConnect.Server
{
    /// <summary>
    /// Provides the logic necessary to extract, validate and handle OpenID Connect requests.
    /// </summary>
    public partial class OpenIdConnectServerHandler : AuthenticationHandler<OpenIdConnectServerOptions>,
        IAuthenticationRequestHandler, IAuthenticationSignInHandler, IAuthenticationSignOutHandler
    {
        public OpenIdConnectServerHandler(
            [NotNull] IOptionsMonitor<OpenIdConnectServerOptions> options,
            [NotNull] ILoggerFactory logger,
            [NotNull] UrlEncoder encoder,
            [NotNull] ISystemClock clock)
            : base(options, logger, encoder, clock) { }

        public virtual async Task<bool> HandleRequestAsync()
        {
            var notification = new MatchEndpointContext(Context, Scheme, Options);

            if (Options.AuthorizationEndpointPath.HasValue &&
                Options.AuthorizationEndpointPath.IsEquivalentTo(Request.Path))
            {
                notification.MatchAuthorizationEndpoint();
            }

            else if (Options.ConfigurationEndpointPath.HasValue &&
                     Options.ConfigurationEndpointPath.IsEquivalentTo(Request.Path))
            {
                notification.MatchConfigurationEndpoint();
            }

            else if (Options.CryptographyEndpointPath.HasValue &&
                     Options.CryptographyEndpointPath.IsEquivalentTo(Request.Path))
            {
                notification.MatchCryptographyEndpoint();
            }

            else if (Options.IntrospectionEndpointPath.HasValue &&
                     Options.IntrospectionEndpointPath.IsEquivalentTo(Request.Path))
            {
                notification.MatchIntrospectionEndpoint();
            }

            else if (Options.LogoutEndpointPath.HasValue &&
                     Options.LogoutEndpointPath.IsEquivalentTo(Request.Path))
            {
                notification.MatchLogoutEndpoint();
            }

            else if (Options.RevocationEndpointPath.HasValue &&
                     Options.RevocationEndpointPath.IsEquivalentTo(Request.Path))
            {
                notification.MatchRevocationEndpoint();
            }

            else if (Options.TokenEndpointPath.HasValue &&
                     Options.TokenEndpointPath.IsEquivalentTo(Request.Path))
            {
                notification.MatchTokenEndpoint();
            }

            else if (Options.UserinfoEndpointPath.HasValue &&
                     Options.UserinfoEndpointPath.IsEquivalentTo(Request.Path))
            {
                notification.MatchUserinfoEndpoint();
            }

            await Provider.MatchEndpoint(notification);

            if (notification.Result != null)
            {
                if (notification.Result.Handled)
                {
                    Logger.LogDebug("The request was handled in user code.");

                    return true;
                }

                else if (notification.Result.Skipped)
                {
                    Logger.LogDebug("The default request handling was skipped from user code.");

                    return false;
                }
            }

            // Reject non-HTTPS requests handled by ASOS if AllowInsecureHttp is not set to true.
            if (!Options.AllowInsecureHttp && !Request.IsHttps)
            {
                // Return the native error page for endpoints involving the user participation.
                if (notification.IsAuthorizationEndpoint || notification.IsLogoutEndpoint)
                {
                    Logger.LogWarning("The current request was rejected because the OpenID Connect server middleware " +
                                      "has been configured to reject HTTP requests. To permanently disable the transport " +
                                      "security requirement, set 'OpenIdConnectServerOptions.AllowInsecureHttp' to 'true'.");

                    return await SendNativePageAsync(new OpenIdConnectResponse
                    {
                        Error = OpenIdConnectConstants.Errors.InvalidRequest,
                        ErrorDescription = "This server only accepts HTTPS requests."
                    });
                }

                // Return a JSON error for endpoints that don't involve the user participation.
                else if (notification.IsConfigurationEndpoint || notification.IsCryptographyEndpoint ||
                         notification.IsIntrospectionEndpoint || notification.IsRevocationEndpoint ||
                         notification.IsTokenEndpoint || notification.IsUserinfoEndpoint)
                {
                    Logger.LogWarning("The current request was rejected because the OpenID Connect server middleware " +
                                      "has been configured to reject HTTP requests. To permanently disable the transport " +
                                      "security requirement, set 'OpenIdConnectServerOptions.AllowInsecureHttp' to 'true'.");

                    return await SendPayloadAsync(new OpenIdConnectResponse
                    {
                        Error = OpenIdConnectConstants.Errors.InvalidRequest,
                        ErrorDescription = "This server only accepts HTTPS requests."
                    });
                }
            }

            if (notification.IsAuthorizationEndpoint)
            {
                return await InvokeAuthorizationEndpointAsync();
            }

            else if (notification.IsConfigurationEndpoint)
            {
                return await InvokeConfigurationEndpointAsync();
            }

            else if (notification.IsCryptographyEndpoint)
            {
                return await InvokeCryptographyEndpointAsync();
            }

            else if (notification.IsIntrospectionEndpoint)
            {
                return await InvokeIntrospectionEndpointAsync();
            }

            else if (notification.IsLogoutEndpoint)
            {
                return await InvokeLogoutEndpointAsync();
            }

            else if (notification.IsRevocationEndpoint)
            {
                return await InvokeRevocationEndpointAsync();
            }

            else if (notification.IsTokenEndpoint)
            {
                return await InvokeTokenEndpointAsync();
            }

            else if (notification.IsUserinfoEndpoint)
            {
                return await InvokeUserinfoEndpointAsync();
            }

            return false;
        }

        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            var request = Context.GetOpenIdConnectRequest();
            if (request == null)
            {
                throw new InvalidOperationException("An identity cannot be extracted from this request.");
            }

            if (request.IsAuthorizationRequest() || request.IsLogoutRequest())
            {
                if (string.IsNullOrEmpty(request.IdTokenHint))
                {
                    return AuthenticateResult.NoResult();
                }

                var ticket = await DeserializeIdentityTokenAsync(request.IdTokenHint, request);
                if (ticket == null)
                {
                    Logger.LogWarning("The identity token extracted from the 'id_token_hint' " +
                                      "parameter was invalid or malformed and was ignored.");

                    return AuthenticateResult.NoResult();
                }

                // Tickets are returned even if they
                // are considered invalid (e.g expired).
                return AuthenticateResult.Success(ticket);
            }

            else if (request.IsTokenRequest())
            {
                // Note: this method can be called from the ApplyTokenResponse event,
                // which may be invoked for a missing authorization code/refresh token.
                if (request.IsAuthorizationCodeGrantType())
                {
                    if (string.IsNullOrEmpty(request.Code))
                    {
                        return AuthenticateResult.NoResult();
                    }

                    var ticket = await DeserializeAuthorizationCodeAsync(request.Code, request);
                    if (ticket == null)
                    {
                        Logger.LogWarning("The authorization code extracted from the " +
                                          "token request was invalid and was ignored.");

                        return AuthenticateResult.NoResult();
                    }

                    return AuthenticateResult.Success(ticket);
                }

                else if (request.IsRefreshTokenGrantType())
                {
                    if (string.IsNullOrEmpty(request.RefreshToken))
                    {
                        return AuthenticateResult.NoResult();
                    }

                    var ticket = await DeserializeRefreshTokenAsync(request.RefreshToken, request);
                    if (ticket == null)
                    {
                        Logger.LogWarning("The refresh token extracted from the " +
                                          "token request was invalid and was ignored.");

                        return AuthenticateResult.NoResult();
                    }

                    return AuthenticateResult.Success(ticket);
                }

                return AuthenticateResult.NoResult();
            }

            throw new InvalidOperationException("An identity cannot be extracted from this request.");
        }

        public virtual Task SignInAsync(ClaimsPrincipal user, AuthenticationProperties properties)
            => SignInAsync(new AuthenticationTicket(user, properties, Scheme.Name));

        private async Task<bool> SignInAsync(AuthenticationTicket ticket)
        {
            // Extract the OpenID Connect request from the ASP.NET Core context.
            // If it cannot be found or doesn't correspond to an authorization
            // or a token request, throw an InvalidOperationException.
            var request = Context.GetOpenIdConnectRequest();
            if (request == null || (!request.IsAuthorizationRequest() && !request.IsTokenRequest()))
            {
                throw new InvalidOperationException("An authorization or token response cannot be returned from this endpoint.");
            }

            // Note: if a response was already generated, throw an exception.
            var response = Context.GetOpenIdConnectResponse();
            if (response != null || Response.HasStarted)
            {
                throw new InvalidOperationException("A response has already been sent.");
            }

            if (string.IsNullOrEmpty(ticket.Principal.GetClaim(OpenIdConnectConstants.Claims.Subject)))
            {
                throw new InvalidOperationException("The authentication ticket was rejected because " +
                                                    "the mandatory subject claim was missing.");
            }

            Logger.LogTrace("A sign-in operation was triggered: {Claims} ; {Properties}.",
                            ticket.Principal.Claims, ticket.Properties.Items);

            // Prepare a new OpenID Connect response.
            response = new OpenIdConnectResponse();

            // Copy the confidentiality level associated with the request to the authentication ticket.
            if (!ticket.HasProperty(OpenIdConnectConstants.Properties.ConfidentialityLevel))
            {
                ticket.SetConfidentialityLevel(request.GetProperty<string>(OpenIdConnectConstants.Properties.ConfidentialityLevel));
            }

            // Always include the "openid" scope when the developer doesn't explicitly call SetScopes.
            // Note: the application is allowed to specify a different "scopes": in this case,
            // don't replace the "scopes" property stored in the authentication ticket.
            if (request.HasScope(OpenIdConnectConstants.Scopes.OpenId) && !ticket.HasScope())
            {
                ticket.SetScopes(OpenIdConnectConstants.Scopes.OpenId);
            }

            // When a "resources" property cannot be found in the ticket,
            // infer it from the "audiences" property.
            if (ticket.HasAudience() && !ticket.HasResource())
            {
                ticket.SetResources(ticket.GetAudiences());
            }

            // Add the validated client_id to the list of authorized presenters,
            // unless the presenters were explicitly set by the developer.
            var presenter = request.GetProperty<string>(OpenIdConnectConstants.Properties.ValidatedClientId);
            if (!string.IsNullOrEmpty(presenter) && !ticket.HasPresenter())
            {
                ticket.SetPresenters(presenter);
            }

            var notification = new ProcessSigninResponseContext(Context, Scheme, Options, ticket, request, response);

            if (request.IsAuthorizationRequest())
            {
                // By default, return an authorization code if a response type containing code was specified.
                notification.IncludeAuthorizationCode = request.HasResponseType(OpenIdConnectConstants.ResponseTypes.Code);

                // By default, return an access token if a response type containing token was specified.
                notification.IncludeAccessToken = request.HasResponseType(OpenIdConnectConstants.ResponseTypes.Token);

                // By default, prevent a refresh token from being returned as the OAuth2 specification
                // explicitly disallows returning a refresh token from the authorization endpoint.
                // See https://tools.ietf.org/html/rfc6749#section-4.2.2 for more information.
                notification.IncludeRefreshToken = false;

                // By default, return an identity token if a response type containing code
                // was specified and if the openid scope was explicitly or implicitly granted.
                notification.IncludeIdentityToken =
                    request.HasResponseType(OpenIdConnectConstants.ResponseTypes.IdToken) &&
                    ticket.HasScope(OpenIdConnectConstants.Scopes.OpenId);
            }

            else
            {
                // By default, prevent an authorization code from being returned as this type of token
                // cannot be issued from the token endpoint in the standard OAuth2/OpenID Connect flows.
                notification.IncludeAuthorizationCode = false;

                // By default, always return an access token.
                notification.IncludeAccessToken = true;

                // By default, only return a refresh token is the offline_access scope was granted and if
                // sliding expiration is disabled or if the request is not a grant_type=refresh_token request.
                notification.IncludeRefreshToken =
                    ticket.HasScope(OpenIdConnectConstants.Scopes.OfflineAccess) &&
                   (Options.UseSlidingExpiration || !request.IsRefreshTokenGrantType());

                // By default, only return an identity token if the openid scope was granted.
                notification.IncludeIdentityToken = ticket.HasScope(OpenIdConnectConstants.Scopes.OpenId);
            }

            await Provider.ProcessSigninResponse(notification);

            if (notification.Result != null)
            {
                if (notification.Result.Handled)
                {
                    Logger.LogDebug("The sign-in response was handled in user code.");

                    return true;
                }

                else if (notification.Result.Skipped)
                {
                    Logger.LogDebug("The default sign-in handling was skipped from user code.");

                    return false;
                }
            }

            else if (notification.IsRejected)
            {
                Logger.LogError("The request was rejected with the following error: {Error} ; {Description}",
                                /* Error: */ notification.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
                                /* Description: */ notification.ErrorDescription);

                if (request.IsAuthorizationRequest())
                {
                    return await SendAuthorizationResponseAsync(new OpenIdConnectResponse
                    {
                        Error = notification.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
                        ErrorDescription = notification.ErrorDescription,
                        ErrorUri = notification.ErrorUri
                    });
                }

                return await SendTokenResponseAsync(new OpenIdConnectResponse
                {
                    Error = notification.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
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
                Logger.LogError("The request was rejected because no authentication ticket was provided.");

                if (request.IsAuthorizationRequest())
                {
                    return await SendAuthorizationResponseAsync(new OpenIdConnectResponse
                    {
                        Error = OpenIdConnectConstants.Errors.AccessDenied,
                        ErrorDescription = "The authorization was denied by the resource owner."
                    });
                }

                return await SendTokenResponseAsync(new OpenIdConnectResponse
                {
                    Error = OpenIdConnectConstants.Errors.InvalidGrant,
                    ErrorDescription = "The token request was rejected by the authorization server."
                });
            }

            if (notification.IncludeAuthorizationCode)
            {
                // Make sure to create a copy of the authentication properties
                // to avoid modifying the properties set on the original ticket.
                var properties = ticket.Properties.Copy();

                response.Code = await SerializeAuthorizationCodeAsync(ticket.Principal, properties, request, response);
            }

            if (notification.IncludeAccessToken)
            {
                // Make sure to create a copy of the authentication properties
                // to avoid modifying the properties set on the original ticket.
                var properties = ticket.Properties.Copy();

                // When receiving a grant_type=refresh_token request, determine whether the client application
                // requests a limited set of scopes and replace the corresponding properties if necessary.
                if (!string.IsNullOrEmpty(request.Scope) && request.IsTokenRequest() && request.IsRefreshTokenGrantType())
                {
                    Logger.LogDebug("The access token scopes will be limited to the scopes requested " +
                                    "by the client application: {Scopes}.", request.GetScopes());

                    // Replace the scopes initially granted by the scopes listed by the client
                    // application in the token request. Note: request.GetScopes() automatically
                    // removes duplicate entries, so additional filtering is not necessary.
                    properties.SetProperty(OpenIdConnectConstants.Properties.Scopes,
                        new JArray(request.GetScopes()).ToString(Formatting.None));
                }

                var scopes = ticket.GetScopes();
                if ((request.IsTokenRequest() && request.IsAuthorizationCodeGrantType()) ||
                    !new HashSet<string>(scopes).SetEquals(request.GetScopes()))
                {
                    response.Scope = string.Join(" ", scopes);
                }

                response.TokenType = OpenIdConnectConstants.TokenTypes.Bearer;
                response.AccessToken = await SerializeAccessTokenAsync(ticket.Principal, properties, request, response);

                // properties.ExpiresUtc is automatically set by SerializeAccessTokenAsync but the end user
                // is free to set a null value directly in the SerializeAccessToken event.
                if (properties.ExpiresUtc.HasValue && properties.ExpiresUtc > Options.SystemClock.UtcNow)
                {
                    var lifetime = properties.ExpiresUtc.Value - Options.SystemClock.UtcNow;

                    response.ExpiresIn = (long) (lifetime.TotalSeconds + .5);
                }
            }

            if (notification.IncludeRefreshToken)
            {
                // Make sure to create a copy of the authentication properties
                // to avoid modifying the properties set on the original ticket.
                var properties = ticket.Properties.Copy();

                response.RefreshToken = await SerializeRefreshTokenAsync(ticket.Principal, properties, request, response);
            }

            if (notification.IncludeIdentityToken)
            {
                // Make sure to create a copy of the authentication properties
                // to avoid modifying the properties set on the original ticket.
                var properties = ticket.Properties.Copy();

                response.IdToken = await SerializeIdentityTokenAsync(ticket.Principal, properties, request, response);
            }

            if (request.IsAuthorizationRequest())
            {
                return await SendAuthorizationResponseAsync(response, ticket);
            }

            return await SendTokenResponseAsync(response, ticket);
        }

        public virtual Task SignOutAsync(AuthenticationProperties properties)
            => HandleSignOutAsync(properties ?? new AuthenticationProperties());

        private async Task<bool> HandleSignOutAsync(AuthenticationProperties properties)
        {
            // Extract the OpenID Connect request from the ASP.NET Core context.
            // If it cannot be found or doesn't correspond to a logout request,
            // throw an InvalidOperationException.
            var request = Context.GetOpenIdConnectRequest();
            if (request == null || !request.IsLogoutRequest())
            {
                throw new InvalidOperationException("A logout response cannot be returned from this endpoint.");
            }

            // Note: if a response was already generated, throw an exception.
            var response = Context.GetOpenIdConnectResponse();
            if (response != null || Response.HasStarted)
            {
                throw new InvalidOperationException("A response has already been sent.");
            }

            Logger.LogTrace("A log-out operation was triggered: {Properties}.", properties.Items);

            // Prepare a new OpenID Connect response.
            response = new OpenIdConnectResponse();

            var notification = new ProcessSignoutResponseContext(Context, Scheme, Options, properties, request, response);
            await Provider.ProcessSignoutResponse(notification);

            if (notification.Result != null)
            {
                if (notification.Result.Handled)
                {
                    Logger.LogDebug("The sign-out response was handled in user code.");

                    return true;
                }

                else if (notification.Result.Skipped)
                {
                    Logger.LogDebug("The default sign-out handling was skipped from user code.");

                    return false;
                }
            }

            else if (notification.IsRejected)
            {
                Logger.LogError("The request was rejected with the following error: {Error} ; {Description}",
                                /* Error: */ notification.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
                                /* Description: */ notification.ErrorDescription);

                return await SendLogoutResponseAsync(new OpenIdConnectResponse
                {
                    Error = notification.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = notification.ErrorDescription,
                    ErrorUri = notification.ErrorUri
                });
            }

            return await SendLogoutResponseAsync(response);
        }

        protected override Task HandleForbiddenAsync(AuthenticationProperties properties)
            => HandleUnauthorizedAsync(properties ?? new AuthenticationProperties());

        protected override Task HandleChallengeAsync(AuthenticationProperties properties)
            => HandleUnauthorizedAsync(properties ?? new AuthenticationProperties());

        private async Task<bool> HandleUnauthorizedAsync(AuthenticationProperties properties)
        {
            // Extract the OpenID Connect request from the ASP.NET Core context.
            // If it cannot be found or doesn't correspond to an authorization
            // or a token request, throw an InvalidOperationException.
            var request = Context.GetOpenIdConnectRequest();
            if (request == null || (!request.IsAuthorizationRequest() && !request.IsTokenRequest()))
            {
                throw new InvalidOperationException("An authorization or token response cannot be returned from this endpoint.");
            }

            // Note: if a response was already generated, throw an exception.
            var response = Context.GetOpenIdConnectResponse();
            if (response != null || Response.HasStarted)
            {
                throw new InvalidOperationException("A response has already been sent.");
            }

            // Prepare a new OpenID Connect response.
            response = new OpenIdConnectResponse
            {
                Error = properties.GetProperty(OpenIdConnectConstants.Properties.Error),
                ErrorDescription = properties.GetProperty(OpenIdConnectConstants.Properties.ErrorDescription),
                ErrorUri = properties.GetProperty(OpenIdConnectConstants.Properties.ErrorUri)
            };

            // Remove the error/error_description/error_uri properties from the ticket.
            properties.RemoveProperty(OpenIdConnectConstants.Properties.Error)
                      .RemoveProperty(OpenIdConnectConstants.Properties.ErrorDescription)
                      .RemoveProperty(OpenIdConnectConstants.Properties.ErrorUri);

            if (string.IsNullOrEmpty(response.Error))
            {
                response.Error = request.IsAuthorizationRequest() ?
                    OpenIdConnectConstants.Errors.AccessDenied :
                    OpenIdConnectConstants.Errors.InvalidGrant;
            }

            if (string.IsNullOrEmpty(response.ErrorDescription))
            {
                response.ErrorDescription = request.IsAuthorizationRequest() ?
                    "The authorization was denied by the resource owner." :
                    "The token request was rejected by the authorization server.";
            }

            Logger.LogTrace("A challenge operation was triggered: {Properties}.", properties.Items);

            var notification = new ProcessChallengeResponseContext(Context, Scheme, Options, properties, request, response);
            await Provider.ProcessChallengeResponse(notification);

            if (notification.Result != null)
            {
                if (notification.Result.Handled)
                {
                    Logger.LogDebug("The challenge response was handled in user code.");

                    return true;
                }

                else if (notification.Result.Skipped)
                {
                    Logger.LogDebug("The default challenge handling was skipped from user code.");

                    return false;
                }
            }

            else if (notification.IsRejected)
            {
                Logger.LogError("The request was rejected with the following error: {Error} ; {Description}",
                                /* Error: */ notification.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
                                /* Description: */ notification.ErrorDescription);

                if (request.IsAuthorizationRequest())
                {
                    return await SendAuthorizationResponseAsync(new OpenIdConnectResponse
                    {
                        Error = notification.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
                        ErrorDescription = notification.ErrorDescription,
                        ErrorUri = notification.ErrorUri
                    });
                }

                return await SendTokenResponseAsync(new OpenIdConnectResponse
                {
                    Error = notification.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = notification.ErrorDescription,
                    ErrorUri = notification.ErrorUri
                });
            }

            // Flow the changes made to the properties.
            properties = notification.Properties;

            // Create a new ticket containing an empty identity and
            // the authentication properties extracted from the context.
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(new ClaimsIdentity()),
                properties, Scheme.Name);

            if (request.IsAuthorizationRequest())
            {
                return await SendAuthorizationResponseAsync(response, ticket);
            }

            return await SendTokenResponseAsync(response, ticket);
        }

        private async Task<bool> SendNativePageAsync(OpenIdConnectResponse response)
        {
            using (var buffer = new MemoryStream())
            using (var writer = new StreamWriter(buffer))
            {
                foreach (var parameter in response.GetParameters())
                {
                    // Ignore null or empty parameters, including JSON
                    // objects that can't be represented as strings.
                    var value = (string) parameter.Value;
                    if (string.IsNullOrEmpty(value))
                    {
                        continue;
                    }

                    writer.WriteLine("{0}:{1}", parameter.Key, value);
                }

                writer.Flush();

                if (!string.IsNullOrEmpty(response.Error))
                {
                    Response.StatusCode = 400;
                }

                Response.ContentLength = buffer.Length;
                Response.ContentType = "text/plain;charset=UTF-8";

                Response.Headers[HeaderNames.CacheControl] = "no-cache";
                Response.Headers[HeaderNames.Pragma] = "no-cache";
                Response.Headers[HeaderNames.Expires] = "Thu, 01 Jan 1970 00:00:00 GMT";

                buffer.Seek(offset: 0, loc: SeekOrigin.Begin);
                await buffer.CopyToAsync(Response.Body, 4096, Context.RequestAborted);

                // Return true to stop processing the request.
                return true;
            }
        }

        private async Task<bool> SendPayloadAsync(OpenIdConnectResponse response)
        {
            using (var buffer = new MemoryStream())
            using (var writer = new JsonTextWriter(new StreamWriter(buffer)))
            {
                var serializer = JsonSerializer.CreateDefault();
                serializer.Serialize(writer, response);

                writer.Flush();

                if (!string.IsNullOrEmpty(response.Error))
                {
                    // When client authentication is made using basic authentication, the authorization server MUST return
                    // a 401 response with a valid WWW-Authenticate header containing the Basic scheme and a non-empty realm.
                    // A similar error MAY be returned even when basic authentication is not used and MUST also be returned
                    // when an invalid token is received by the userinfo endpoint using the Bearer authentication scheme.
                    // To simplify the logic, a 401 response with the Bearer scheme is returned for invalid_token errors
                    // and a 401 response with the Basic scheme is returned for invalid_client, even if the credentials
                    // were specified in the request form instead of the HTTP headers, as allowed by the specification.
                    string GetAuthenticationScheme()
                    {
                        switch (response.Error)
                        {
                            case OpenIdConnectConstants.Errors.InvalidClient: return OpenIdConnectConstants.Schemes.Basic;
                            case OpenIdConnectConstants.Errors.InvalidToken:  return OpenIdConnectConstants.Schemes.Bearer;
                            default:                                          return null;
                        }
                    }

                    var scheme = GetAuthenticationScheme();
                    if (!string.IsNullOrEmpty(scheme))
                    {
                        Response.StatusCode = 401;

                        Response.Headers[HeaderNames.WWWAuthenticate] = new StringBuilder()
                            .Append(scheme)
                            .Append(' ')
                            .Append(OpenIdConnectConstants.Parameters.Realm)
                            .Append("=\"")
                            .Append(Context.GetIssuer(Options))
                            .Append('"')
                            .ToString();
                    }

                    else
                    {
                        Response.StatusCode = 400;
                    }
                }

                Response.ContentLength = buffer.Length;
                Response.ContentType = "application/json;charset=UTF-8";

                switch (response.GetProperty<string>(OpenIdConnectConstants.Properties.MessageType))
                {
                    // Discovery, userinfo and introspection responses can be cached by the client
                    // or the intermediate proxies. To allow the developer to set up his own response
                    // caching policy, don't override the Cache-Control, Pragma and Expires headers.
                    case OpenIdConnectConstants.MessageTypes.ConfigurationResponse:
                    case OpenIdConnectConstants.MessageTypes.CryptographyResponse:
                    case OpenIdConnectConstants.MessageTypes.IntrospectionResponse:
                    case OpenIdConnectConstants.MessageTypes.UserinfoResponse:
                        break;

                    // Prevent the other responses from being cached.
                    default:
                        Response.Headers[HeaderNames.CacheControl] = "no-cache";
                        Response.Headers[HeaderNames.Pragma] = "no-cache";
                        Response.Headers[HeaderNames.Expires] = "Thu, 01 Jan 1970 00:00:00 GMT";

                        break;
                }

                buffer.Seek(offset: 0, loc: SeekOrigin.Begin);
                await buffer.CopyToAsync(Response.Body, 4096, Context.RequestAborted);

                // Return true to stop processing the request.
                return true;
            }
        }

        private OpenIdConnectServerProvider Provider => (OpenIdConnectServerProvider) base.Events;
    }
}
