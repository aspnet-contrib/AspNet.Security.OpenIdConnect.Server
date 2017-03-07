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
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Extensions;
using AspNet.Security.OpenIdConnect.Primitives;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http.Authentication;
using Microsoft.AspNetCore.Http.Features.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Net.Http.Headers;
using Newtonsoft.Json;

namespace AspNet.Security.OpenIdConnect.Server
{
    public partial class OpenIdConnectServerHandler : AuthenticationHandler<OpenIdConnectServerOptions>
    {
        public override async Task<bool> HandleRequestAsync()
        {
            var notification = new MatchEndpointContext(Context, Options);

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

            await Options.Provider.MatchEndpoint(notification);

            if (notification.HandledResponse)
            {
                Logger.LogDebug("The request was handled in user code.");

                return true;
            }

            else if (notification.Skipped)
            {
                Logger.LogDebug("The default request handling was skipped from user code.");

                return false;
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
                    return AuthenticateResult.Skip();
                }

                var ticket = await DeserializeIdentityTokenAsync(request.IdTokenHint, request);
                if (ticket == null)
                {
                    Logger.LogWarning("The identity token extracted from the id_token_hint " +
                                      "parameter was invalid and has been ignored.");

                    return AuthenticateResult.Skip();
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
                        return AuthenticateResult.Skip();
                    }

                    var ticket = await DeserializeAuthorizationCodeAsync(request.Code, request);
                    if (ticket == null)
                    {
                        Logger.LogWarning("The authorization code extracted from the " +
                                          "token request was invalid and has been ignored.");

                        return AuthenticateResult.Skip();
                    }

                    return AuthenticateResult.Success(ticket);
                }

                else if (request.IsRefreshTokenGrantType())
                {
                    if (string.IsNullOrEmpty(request.RefreshToken))
                    {
                        return AuthenticateResult.Skip();
                    }

                    var ticket = await DeserializeRefreshTokenAsync(request.RefreshToken, request);
                    if (ticket == null)
                    {
                        Logger.LogWarning("The refresh token extracted from the " +
                                          "token request was invalid and has been ignored.");

                        return AuthenticateResult.Skip();
                    }

                    return AuthenticateResult.Success(ticket);
                }

                return AuthenticateResult.Skip();
            }

            throw new InvalidOperationException("An identity cannot be extracted from this request.");
        }

        protected override Task HandleSignInAsync(SignInContext context)
        {
            var ticket = new AuthenticationTicket(context.Principal,
                new AuthenticationProperties(context.Properties),
                context.AuthenticationScheme);

            return HandleSignInAsync(ticket);
        }

        private async Task<bool> HandleSignInAsync(AuthenticationTicket ticket)
        {
            // Extract the OpenID Connect request from the ASP.NET context.
            // If it cannot be found or doesn't correspond to an authorization
            // or a token request, throw an InvalidOperationException.
            var request = Context.GetOpenIdConnectRequest();
            if (request == null || (!request.IsAuthorizationRequest() && !request.IsTokenRequest()))
            {
                throw new InvalidOperationException("An OpenID Connect response cannot be returned from this endpoint.");
            }

            // Note: if an OpenID Connect response was already generated, throw an exception.
            var response = Context.GetOpenIdConnectResponse();
            if (response != null)
            {
                throw new InvalidOperationException("An OpenID Connect response has already been sent.");
            }

            if (string.IsNullOrEmpty(ticket.Principal.GetClaim(OpenIdConnectConstants.Claims.Subject)))
            {
                throw new InvalidOperationException("The authentication ticket was rejected because " +
                                                    "it doesn't contain the mandatory subject claim.");
            }

            // Prepare a new OpenID Connect response.
            response = new OpenIdConnectResponse();

            if (request.IsAuthorizationRequest())
            {
                response.RedirectUri = request.GetProperty<string>(OpenIdConnectConstants.Properties.RedirectUri);
                response.State = request.State;
            }

            // Copy the confidentiality level associated with the request to the authentication ticket.
            if (!ticket.HasProperty(OpenIdConnectConstants.Properties.ConfidentialityLevel))
            {
                ticket.SetProperty(OpenIdConnectConstants.Properties.ConfidentialityLevel,
                    request.GetProperty<string>(OpenIdConnectConstants.Properties.ConfidentialityLevel));
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
            var presenter = request.GetProperty<string>(OpenIdConnectConstants.Properties.ClientId);
            if (!string.IsNullOrEmpty(presenter) && !ticket.HasPresenter())
            {
                ticket.SetPresenters(presenter);
            }

            // Only return an authorization code if the request is an authorization request and has response_type=code.
            if (request.IsAuthorizationRequest() && request.HasResponseType(OpenIdConnectConstants.ResponseTypes.Code))
            {
                // Make sure to create a copy of the authentication properties
                // to avoid modifying the properties set on the original ticket.
                var properties = ticket.Properties.Copy();

                response.Code = await SerializeAuthorizationCodeAsync(ticket.Principal, properties, request, response);
            }

            // Only return an access token if the request is a token request
            // or an authorization request that specifies response_type=token.
            if (request.IsTokenRequest() || (request.IsAuthorizationRequest() &&
                                             request.HasResponseType(OpenIdConnectConstants.ResponseTypes.Token)))
            {
                // Make sure to create a copy of the authentication properties
                // to avoid modifying the properties set on the original ticket.
                var properties = ticket.Properties.Copy();

                // When receiving a grant_type=refresh_token request, determine whether the client application
                // requests a limited set of scopes/resources and replace the corresponding properties if necessary.
                // Note: at this stage, request.GetResources() cannot return more items than the ones that were initially granted
                // by the resource owner as the "resources" parameter is always validated when receiving the token request.
                if (request.IsTokenRequest() && request.IsRefreshTokenGrantType())
                {
                    if (!string.IsNullOrEmpty(request.Resource))
                    {
                        Logger.LogDebug("The access token resources will be limited to the resources " +
                                        "requested by the client application: {Resources}.", request.GetResources());

                        // Replace the resources initially granted by the resources listed by the client application in the token request.
                        // Note: request.GetResources() automatically removes duplicate entries, so additional filtering is not necessary.
                        properties.SetProperty(OpenIdConnectConstants.Properties.Resources, request.GetResources());
                    }

                    if (!string.IsNullOrEmpty(request.Scope))
                    {
                        Logger.LogDebug("The access token scopes will be limited to the scopes " +
                                        "requested by the client application: {Scopes}.", request.GetScopes());

                        // Replace the scopes initially granted by the scopes listed by the client application in the token request.
                        // Note: request.GetScopes() automatically removes duplicate entries, so additional filtering is not necessary.
                        properties.SetProperty(OpenIdConnectConstants.Properties.Scopes, request.GetScopes());
                    }
                }

                var resources = ticket.GetResources();
                if (request.IsAuthorizationCodeGrantType() || !new HashSet<string>(resources).SetEquals(request.GetResources()))
                {
                    response.Resource = string.Join(" ", resources);
                }

                var scopes = ticket.GetScopes();
                if (request.IsAuthorizationCodeGrantType() || !new HashSet<string>(scopes).SetEquals(request.GetScopes()))
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

            // Only return a refresh token if the request is a token request that specifies scope=offline_access.
            if (request.IsTokenRequest() && ticket.HasScope(OpenIdConnectConstants.Scopes.OfflineAccess))
            {
                // Note: when sliding expiration is disabled, don't return a new refresh token,
                // unless the token request is not a grant_type=refresh_token request.
                if (Options.UseSlidingExpiration || !request.IsRefreshTokenGrantType())
                {
                    // Make sure to create a copy of the authentication properties
                    // to avoid modifying the properties set on the original ticket.
                    var properties = ticket.Properties.Copy();

                    response.RefreshToken = await SerializeRefreshTokenAsync(ticket.Principal, properties, request, response);
                }
            }

            // Only return an identity token if the openid scope was requested and granted
            // to avoid generating and returning an unnecessary token to pure OAuth2 clients.
            if (ticket.HasScope(OpenIdConnectConstants.Scopes.OpenId))
            {
                // Note: don't return an identity token if the request is an
                // authorization request that doesn't use response_type=id_token.
                if (request.IsTokenRequest() || request.HasResponseType(OpenIdConnectConstants.ResponseTypes.IdToken))
                {
                    // Make sure to create a copy of the authentication properties
                    // to avoid modifying the properties set on the original ticket.
                    var properties = ticket.Properties.Copy();

                    response.IdToken = await SerializeIdentityTokenAsync(ticket.Principal, properties, request, response);
                }
            }

            if (request.IsAuthorizationRequest())
            {
                return await SendAuthorizationResponseAsync(response, ticket);
            }

            return await SendTokenResponseAsync(response, ticket);
        }

        protected override Task HandleSignOutAsync(SignOutContext context)
        {
            // Extract the OpenID Connect request from the ASP.NET context.
            // If it cannot be found or doesn't correspond to a logout request,
            // throw an InvalidOperationException.
            var request = Context.GetOpenIdConnectRequest();
            if (request == null || !request.IsLogoutRequest())
            {
                throw new InvalidOperationException("An OpenID Connect response cannot be returned from this endpoint.");
            }

            // Note: if an OpenID Connect response was already generated, throw an exception.
            var response = Context.GetOpenIdConnectResponse();
            if (response != null)
            {
                throw new InvalidOperationException("An OpenID Connect response has already been sent.");
            }

            // Prepare a new OpenID Connect response.
            response = new OpenIdConnectResponse
            {
                PostLogoutRedirectUri = request.GetProperty<string>(OpenIdConnectConstants.Properties.PostLogoutRedirectUri),
                State = request.State
            };

            return SendLogoutResponseAsync(response);
        }

        protected override Task<bool> HandleForbiddenAsync(ChallengeContext context) => HandleUnauthorizedAsync(context);

        protected override async Task<bool> HandleUnauthorizedAsync(ChallengeContext context)
        {
            // Extract the OpenID Connect request from the ASP.NET context.
            // If it cannot be found or doesn't correspond to an authorization
            // or a token request, throw an InvalidOperationException.
            var request = Context.GetOpenIdConnectRequest();
            if (request == null || (!request.IsAuthorizationRequest() && !request.IsTokenRequest()))
            {
                throw new InvalidOperationException("An OpenID Connect response cannot be returned from this endpoint.");
            }

            // Note: if an OpenID Connect response was already generated, throw an exception.
            var response = Context.GetOpenIdConnectResponse();
            if (response != null)
            {
                throw new InvalidOperationException("An OpenID Connect response has already been sent.");
            }

            // Create a new ticket containing an empty identity and
            // the authentication properties extracted from the challenge.
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(new ClaimsIdentity()),
                new AuthenticationProperties(context.Properties),
                context.AuthenticationScheme);

            // Prepare a new OpenID Connect response.
            response = new OpenIdConnectResponse
            {
                Error = ticket.GetProperty(OpenIdConnectConstants.Properties.Error),
                ErrorDescription = ticket.GetProperty(OpenIdConnectConstants.Properties.ErrorDescription),
                ErrorUri = ticket.GetProperty(OpenIdConnectConstants.Properties.ErrorUri)
            };

            // Remove the error/error_description/error_uri properties from the ticket.
            ticket.RemoveProperty(OpenIdConnectConstants.Properties.Error)
                  .RemoveProperty(OpenIdConnectConstants.Properties.ErrorDescription)
                  .RemoveProperty(OpenIdConnectConstants.Properties.ErrorUri);

            // If the request is an authorization request, attach the
            // redirect_uri and the state to the OpenID Connect response.
            if (request.IsAuthorizationRequest())
            {
                response.RedirectUri = request.GetProperty<string>(OpenIdConnectConstants.Properties.RedirectUri);
                response.State = request.State;
            }

            if (string.IsNullOrEmpty(response.Error))
            {
                response.Error = request.IsAuthorizationRequest() ?
                    OpenIdConnectConstants.Errors.AccessDenied :
                    OpenIdConnectConstants.Errors.InvalidGrant;
            }

            if (string.IsNullOrEmpty(response.ErrorDescription))
            {
                response.ErrorDescription = request.IsAuthorizationRequest() ?
                    "The authorization grant has been denied by the resource owner." :
                    "The token request was rejected by the authorization server.";
            }

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
                Response.Headers[HeaderNames.Expires] = "-1";

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
                    Response.StatusCode = 400;
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
                        Response.Headers[HeaderNames.Expires] = "-1";

                        break;
                }

                buffer.Seek(offset: 0, loc: SeekOrigin.Begin);
                await buffer.CopyToAsync(Response.Body, 4096, Context.RequestAborted);

                // Return true to stop processing the request.
                return true;
            }
        }

        private class Appender
        {
            private readonly char _delimiter;
            private readonly StringBuilder _sb;
            private bool _hasDelimiter;

            public Appender(string value, char delimiter)
            {
                _sb = new StringBuilder(value);
                _delimiter = delimiter;
                _hasDelimiter = value.IndexOf(delimiter) != -1;
            }

            public Appender Append(string name, string value)
            {
                _sb.Append(_hasDelimiter ? '&' : _delimiter)
                   .Append(Uri.EscapeDataString(name))
                   .Append('=')
                   .Append(Uri.EscapeDataString(value));
                _hasDelimiter = true;
                return this;
            }

            public override string ToString()
            {
                return _sb.ToString();
            }
        }
    }
}
