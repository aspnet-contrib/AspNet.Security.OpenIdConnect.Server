/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.IO;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Extensions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Authentication;
using Microsoft.AspNetCore.Http.Features.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Net.Http.Headers;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace AspNet.Security.OpenIdConnect.Server {
    internal partial class OpenIdConnectServerHandler : AuthenticationHandler<OpenIdConnectServerOptions> {
        protected override async Task<AuthenticateResult> HandleAuthenticateAsync() {
            var notification = new MatchEndpointContext(Context, Options);

            if (Options.AuthorizationEndpointPath.HasValue &&
                Options.AuthorizationEndpointPath == Request.Path) {
                notification.MatchesAuthorizationEndpoint();
            }

            else if (Options.LogoutEndpointPath.HasValue &&
                     Options.LogoutEndpointPath == Request.Path) {
                notification.MatchesLogoutEndpoint();
            }

            else if (Options.UserinfoEndpointPath.HasValue &&
                     Options.UserinfoEndpointPath == Request.Path) {
                notification.MatchesUserinfoEndpoint();
            }

            await Options.Provider.MatchEndpoint(notification);

            if (!notification.IsAuthorizationEndpoint &&
                !notification.IsLogoutEndpoint &&
                !notification.IsUserinfoEndpoint) {
                return AuthenticateResult.Skip();
            }

            // Try to retrieve the current OpenID Connect request from the ASP.NET context.
            // If the request cannot be found, this means that this middleware was configured
            // to use the automatic authentication mode and that HandleAuthenticateAsync
            // was invoked before Invoke*EndpointAsync: in this case, the OpenID Connect
            // request is directly extracted from the query string or the request form.
            var request = Context.GetOpenIdConnectRequest();
            if (request == null) {
                if (string.Equals(Request.Method, "GET", StringComparison.OrdinalIgnoreCase)) {
                    request = new OpenIdConnectRequest(Request.Query);
                }

                else if (string.Equals(Request.Method, "POST", StringComparison.OrdinalIgnoreCase)) {
                    if (string.IsNullOrEmpty(Request.ContentType)) {
                        return AuthenticateResult.Skip();
                    }

                    else if (!Request.ContentType.StartsWith("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase)) {
                        return AuthenticateResult.Skip();
                    }

                    request = new OpenIdConnectRequest(await Request.ReadFormAsync(Context.RequestAborted));
                }
            }

            // Missing or invalid requests are ignored in HandleAuthenticateAsync:
            // in this case, Skip is used to indicate that authentication failed.
            if (request == null) {
                return AuthenticateResult.Skip();
            }

            if (notification.IsAuthorizationEndpoint || notification.IsLogoutEndpoint) {
                if (string.IsNullOrEmpty(request.IdTokenHint)) {
                    return AuthenticateResult.Skip();
                }

                var ticket = await DeserializeIdentityTokenAsync(request.IdTokenHint, request);
                if (ticket == null) {
                    Logger.LogWarning("The identity token extracted from the id_token_hint " +
                                      "parameter was invalid and has been ignored.");

                    return AuthenticateResult.Skip();
                }

                // Tickets are returned even if they
                // are considered invalid (e.g expired).
                return AuthenticateResult.Success(ticket);
            }

            else if (notification.IsUserinfoEndpoint) {
                string token;
                if (!string.IsNullOrEmpty(request.AccessToken)) {
                    token = request.AccessToken;
                }

                else {
                    string header = Request.Headers[HeaderNames.Authorization];
                    if (string.IsNullOrEmpty(header)) {
                        return AuthenticateResult.Skip();
                    }

                    if (!header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)) {
                        return AuthenticateResult.Skip();
                    }

                    token = header.Substring("Bearer ".Length);
                    if (string.IsNullOrWhiteSpace(token)) {
                        return AuthenticateResult.Skip();
                    }
                }

                var ticket = await DeserializeAccessTokenAsync(token, request);
                if (ticket == null) {
                    Logger.LogWarning("The access token extracted from the userinfo " +
                                      "request was expired and has been ignored.");

                    return AuthenticateResult.Skip();
                }

                if (!ticket.Properties.ExpiresUtc.HasValue ||
                     ticket.Properties.ExpiresUtc < Options.SystemClock.UtcNow) {
                    Logger.LogWarning("The access token extracted from the userinfo " +
                                      "request was expired and has been ignored.");

                    return AuthenticateResult.Skip();
                }

                return AuthenticateResult.Success(ticket);
            }

            return AuthenticateResult.Skip();
        }

        public override async Task<bool> HandleRequestAsync() {
            var notification = new MatchEndpointContext(Context, Options);

            if (Options.AuthorizationEndpointPath.HasValue &&
                Options.AuthorizationEndpointPath == Request.Path) {
                notification.MatchesAuthorizationEndpoint();
            }

            else if (Options.ConfigurationEndpointPath.HasValue &&
                     Options.ConfigurationEndpointPath == Request.Path) {
                notification.MatchesConfigurationEndpoint();
            }

            else if (Options.CryptographyEndpointPath.HasValue &&
                     Options.CryptographyEndpointPath == Request.Path) {
                notification.MatchesCryptographyEndpoint();
            }

            else if (Options.IntrospectionEndpointPath.HasValue &&
                     Options.IntrospectionEndpointPath == Request.Path) {
                notification.MatchesIntrospectionEndpoint();
            }

            else if (Options.LogoutEndpointPath.HasValue &&
                     Options.LogoutEndpointPath == Request.Path) {
                notification.MatchesLogoutEndpoint();
            }

            else if (Options.RevocationEndpointPath.HasValue &&
                     Options.RevocationEndpointPath == Request.Path) {
                notification.MatchesRevocationEndpoint();
            }

            else if (Options.TokenEndpointPath.HasValue &&
                     Options.TokenEndpointPath == Request.Path) {
                notification.MatchesTokenEndpoint();
            }

            else if (Options.UserinfoEndpointPath.HasValue &&
                     Options.UserinfoEndpointPath == Request.Path) {
                notification.MatchesUserinfoEndpoint();
            }

            await Options.Provider.MatchEndpoint(notification);

            if (notification.HandledResponse) {
                return true;
            }

            else if (notification.Skipped) {
                return false;
            }

            // Reject non-HTTPS requests handled by ASOS if AllowInsecureHttp is not set to true.
            if (!Options.AllowInsecureHttp && !Request.IsHttps) {
                // Return the native error page for endpoints involving the user participation.
                if (notification.IsAuthorizationEndpoint || notification.IsLogoutEndpoint) {
                    Logger.LogWarning("The current request was rejected because the OpenID Connect server middleware " +
                                      "has been configured to reject HTTP requests. To permanently disable the transport " +
                                      "security requirement, set 'OpenIdConnectServerOptions.AllowInsecureHttp' to 'true'.");

                    return await SendNativePageAsync(new OpenIdConnectResponse {
                        Error = OpenIdConnectConstants.Errors.InvalidRequest,
                        ErrorDescription = "This server only accepts HTTPS requests."
                    });
                }

                // Return a JSON error for endpoints that don't involve the user participation.
                else if (notification.IsConfigurationEndpoint || notification.IsCryptographyEndpoint ||
                         notification.IsIntrospectionEndpoint || notification.IsRevocationEndpoint ||
                         notification.IsTokenEndpoint || notification.IsUserinfoEndpoint) {
                    Logger.LogWarning("The current request was rejected because the OpenID Connect server middleware " +
                                      "has been configured to reject HTTP requests. To permanently disable the transport " +
                                      "security requirement, set 'OpenIdConnectServerOptions.AllowInsecureHttp' to 'true'.");

                    return await SendPayloadAsync(new OpenIdConnectResponse {
                        Error = OpenIdConnectConstants.Errors.InvalidRequest,
                        ErrorDescription = "This server only accepts HTTPS requests."
                    });
                }
            }

            if (notification.IsAuthorizationEndpoint) {
                return await InvokeAuthorizationEndpointAsync();
            }

            else if (notification.IsConfigurationEndpoint) {
                return await InvokeConfigurationEndpointAsync();
            }

            else if (notification.IsCryptographyEndpoint) {
                return await InvokeCryptographyEndpointAsync();
            }

            else if (notification.IsIntrospectionEndpoint) {
                return await InvokeIntrospectionEndpointAsync();
            }

            else if (notification.IsLogoutEndpoint) {
                return await InvokeLogoutEndpointAsync();
            }

            else if (notification.IsRevocationEndpoint) {
                return await InvokeRevocationEndpointAsync();
            }

            else if (notification.IsTokenEndpoint) {
                return await InvokeTokenEndpointAsync();
            }

            else if (notification.IsUserinfoEndpoint) {
                return await InvokeUserinfoEndpointAsync();
            }

            return false;
        }

        protected override Task HandleSignInAsync(SignInContext context) {
            // request may be null when no authorization request has been received
            // or has been already handled by InvokeAuthorizationEndpointAsync.
            var request = Context.GetOpenIdConnectRequest();
            if (request == null) {
                return Task.FromResult(0);
            }

            // Stop processing the request if there's no response grant that matches
            // the authentication type associated with this middleware instance
            // or if the response status code doesn't indicate a successful response.
            if (context == null || Response.StatusCode != 200) {
                return Task.FromResult(0);
            }

            var ticket = new AuthenticationTicket(context.Principal,
                new AuthenticationProperties(context.Properties),
                context.AuthenticationScheme);

            return HandleSignInAsync(ticket);
        }

        private async Task<bool> HandleSignInAsync(AuthenticationTicket ticket) {
            // Extract the OpenID Connect request from the ASP.NET context. If it cannot
            // be found or doesn't correspond to an authorization or token request,
            // return false to allow the other middleware to process the signin response.
            var request = Context.GetOpenIdConnectRequest();
            if (request == null || (!request.IsAuthorizationRequest() && !request.IsTokenRequest())) {
                return false;
            }

            // Note: if an OpenID Connect response was already generated,
            // return immediately to avoid overwriting it.
            var response = Context.GetOpenIdConnectResponse();
            if (response != null) {
                return false;
            }

            if (!ticket.Principal.HasClaim(claim => claim.Type == ClaimTypes.NameIdentifier)) {
                throw new InvalidOperationException("The authentication ticket was rejected because it didn't " +
                                                    "contain the mandatory ClaimTypes.NameIdentifier claim.");
            }

            // Prepare a new OpenID Connect response.
            response = new OpenIdConnectResponse();

            if (request.IsAuthorizationRequest()) {
                response.RedirectUri = request.RedirectUri;
                response.State = request.State;

                // Keep the code_challenge, code_challenge_method, nonce and redirect_uri parameters for later comparison.
                ticket.SetProperty(OpenIdConnectConstants.Properties.CodeChallenge, request.CodeChallenge);
                ticket.SetProperty(OpenIdConnectConstants.Properties.CodeChallengeMethod, request.CodeChallengeMethod);
                ticket.SetProperty(OpenIdConnectConstants.Properties.Nonce, request.Nonce);
                ticket.SetProperty(OpenIdConnectConstants.Properties.RedirectUri, request.RedirectUri);
            }

            // Store a boolean indicating whether the ticket should be marked as confidential.
            if (request.IsConfidential && request.IsTokenRequest()) {
                ticket.SetProperty(OpenIdConnectConstants.Properties.Confidential, "true");
            }

            // Always include the "openid" scope when the developer doesn't explicitly call SetScopes.
            // Note: the application is allowed to specify a different "scopes": in this case,
            // don't replace the "scopes" property stored in the authentication ticket.
            if (!ticket.HasProperty(OpenIdConnectConstants.Properties.Scopes) && request.HasScope(OpenIdConnectConstants.Scopes.OpenId)) {
                ticket.SetProperty(OpenIdConnectConstants.Properties.Scopes, OpenIdConnectConstants.Scopes.OpenId);
            }

            // When a "resources" property cannot be found in the ticket, infer it from the "audiences" property.
            if (!ticket.HasProperty(OpenIdConnectConstants.Properties.Resources)) {
                var audiences = ticket.GetProperty(OpenIdConnectConstants.Properties.Audiences);

                ticket.SetProperty(OpenIdConnectConstants.Properties.Resources, audiences);
            }

            // Only return an authorization code if the request is an authorization request and has response_type=code.
            if (request.IsAuthorizationRequest() && request.HasResponseType(OpenIdConnectConstants.ResponseTypes.Code)) {
                // Make sure to create a copy of the authentication properties
                // to avoid modifying the properties set on the original ticket.
                var properties = ticket.Properties.Copy();

                // properties.IssuedUtc and properties.ExpiresUtc are always
                // explicitly set to null to avoid aligning the expiration date
                // of the authorization code with the lifetime of the other tokens.
                properties.IssuedUtc = properties.ExpiresUtc = null;

                response.Code = await SerializeAuthorizationCodeAsync(ticket.Principal, properties, request, response);
            }

            // Only return an access token if the request is a token request
            // or an authorization request that specifies response_type=token.
            if (request.IsTokenRequest() || (request.IsAuthorizationRequest() &&
                                             request.HasResponseType(OpenIdConnectConstants.ResponseTypes.Token))) {
                // Make sure to create a copy of the authentication properties
                // to avoid modifying the properties set on the original ticket.
                var properties = ticket.Properties.Copy();

                // When receiving a grant_type=refresh_token request, determine whether the client application
                // requests a limited set of scopes/resources and replace the corresponding properties if necessary.
                // Note: at this stage, request.GetResources() cannot return more items than the ones that were initially granted
                // by the resource owner as the "resources" parameter is always validated when receiving the token request.
                if (request.IsTokenRequest() && request.IsRefreshTokenGrantType()) {
                    if (!string.IsNullOrEmpty(request.Resource)) {
                        // Replace the resources initially granted by the resources listed by the client application in the token request.
                        // Note: request.GetResources() automatically removes duplicate entries, so additional filtering is not necessary.
                        properties.SetProperty(OpenIdConnectConstants.Properties.Resources, string.Join(" ", request.GetResources()));
                    }

                    if (!string.IsNullOrEmpty(request.Scope)) {
                        // Replace the scopes initially granted by the scopes listed by the client application in the token request.
                        // Note: request.GetScopes() automatically removes duplicate entries, so additional filtering is not necessary.
                        properties.SetProperty(OpenIdConnectConstants.Properties.Scopes, string.Join(" ", request.GetScopes()));
                    }
                }

                // Note: when the resource/scope parameters added to the OpenID Connect response
                // are identical to the request parameters, returning them is not necessary.
                if (request.IsAuthorizationRequest() || (request.IsTokenRequest() && request.IsAuthorizationCodeGrantType())) {
                    var resources = properties.GetProperty(OpenIdConnectConstants.Properties.Resources);
                    if (request.IsAuthorizationCodeGrantType() || (!string.IsNullOrEmpty(resources) &&
                                                                   !string.IsNullOrEmpty(request.Resource) &&
                                                                   !string.Equals(request.Resource, resources, StringComparison.Ordinal))) {
                        response.Resource = resources;
                    }

                    var scopes = properties.GetProperty(OpenIdConnectConstants.Properties.Scopes);
                    if (request.IsAuthorizationCodeGrantType() || (!string.IsNullOrEmpty(scopes) &&
                                                                   !string.IsNullOrEmpty(request.Scope) &&
                                                                   !string.Equals(request.Scope, scopes, StringComparison.Ordinal))) {
                        response.Scope = scopes;
                    }
                }

                response.TokenType = OpenIdConnectConstants.TokenTypes.Bearer;
                response.AccessToken = await SerializeAccessTokenAsync(ticket.Principal, properties, request, response);

                // properties.ExpiresUtc is automatically set by SerializeAccessTokenAsync but the end user
                // is free to set a null value directly in the SerializeAccessToken event.
                if (properties.ExpiresUtc.HasValue && properties.ExpiresUtc > Options.SystemClock.UtcNow) {
                    var lifetime = properties.ExpiresUtc.Value - Options.SystemClock.UtcNow;

                    response.ExpiresIn = (long) (lifetime.TotalSeconds + .5);
                }
            }

            // Only return a refresh token if the request is a token request that specifies scope=offline_access.
            if (request.IsTokenRequest() && ticket.HasScope(OpenIdConnectConstants.Scopes.OfflineAccess)) {
                // Note: when sliding expiration is enabled, don't return a new refresh token,
                // unless the token request is not a grant_type=refresh_token request.
                if (!request.IsRefreshTokenGrantType() || Options.UseSlidingExpiration) {
                    // Make sure to create a copy of the authentication properties
                    // to avoid modifying the properties set on the original ticket.
                    var properties = ticket.Properties.Copy();

                    response.RefreshToken = await SerializeRefreshTokenAsync(ticket.Principal, properties, request, response);
                }
            }

            // Only return an identity token if the openid scope was requested and granted
            // to avoid generating and returning an unnecessary token to pure OAuth2 clients.
            if (ticket.HasScope(OpenIdConnectConstants.Scopes.OpenId)) {
                // Note: don't return an identity token if the request is an
                // authorization request that doesn't use response_type=id_token.
                if (request.IsTokenRequest() || request.HasResponseType(OpenIdConnectConstants.ResponseTypes.IdToken)) {
                    // Make sure to create a copy of the authentication properties
                    // to avoid modifying the properties set on the original ticket.
                    var properties = ticket.Properties.Copy();

                    // properties.IssuedUtc and properties.ExpiresUtc are always
                    // explicitly set to null to avoid aligning the expiration date
                    // of the identity token with the lifetime of the other tokens.
                    properties.IssuedUtc = properties.ExpiresUtc = null;

                    response.IdToken = await SerializeIdentityTokenAsync(ticket.Principal, properties, request, response);
                }
            }

            if (request.IsAuthorizationRequest()) {
                return await SendAuthorizationResponseAsync(request, response, ticket);
            }

            return await SendTokenResponseAsync(request, response, ticket);
        }

        protected override Task HandleSignOutAsync(SignOutContext context) {
            // Extract the OpenID Connect request from the ASP.NET context.
            // If it cannot be found or doesn't correspond to a logout request,
            // return false to allow the other middleware to process the challenge.
            var request = Context.GetOpenIdConnectRequest();
            if (request == null || !request.IsLogoutRequest()) {
                return Task.FromResult(0);
            }

            // Note: if an OpenID Connect response was already generated,
            // return immediately to avoid overwriting it.
            var response = Context.GetOpenIdConnectResponse();
            if (response != null) {
                return Task.FromResult(false);
            }

            // Prepare a new OpenID Connect response.
            response = new OpenIdConnectResponse {
                PostLogoutRedirectUri = request.PostLogoutRedirectUri,
                State = request.State
            };

            return SendLogoutResponseAsync(request, response);
        }

        protected override Task<bool> HandleForbiddenAsync(ChallengeContext context) {
            // Extract the OpenID Connect request from the ASP.NET context. If it cannot
            // be found or doesn't correspond to an authorization or token request,
            // return false to allow the other middleware to process the challenge.
            var request = Context.GetOpenIdConnectRequest();
            if (request == null || (!request.IsAuthorizationRequest() && !request.IsTokenRequest())) {
                return Task.FromResult(false);
            }

            // Note: if an OpenID Connect response was already generated,
            // return immediately to avoid overwriting it.
            var response = Context.GetOpenIdConnectResponse();
            if (response != null) {
                return Task.FromResult(false);
            }

            // Prepare a new OpenID Connect response.
            response = new OpenIdConnectResponse();

            if (request.IsAuthorizationRequest()) {
                response.RedirectUri = request.RedirectUri;
                response.State = request.State;

                response.Error = OpenIdConnectConstants.Errors.AccessDenied;
                response.ErrorDescription = "The authorization grant has been denied by the resource owner.";
            }

            else {
                response.Error = OpenIdConnectConstants.Errors.InvalidGrant;
                response.ErrorDescription = "The token request was rejected by the authorization server.";
            }

            // Create a new ticket containing an empty identity and
            // the authentication properties extracted from the challenge.
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(),
                new AuthenticationProperties(context.Properties),
                context.AuthenticationScheme);

            if (request.IsAuthorizationRequest()) {
                return SendAuthorizationResponseAsync(request, response, ticket);
            }

            return SendTokenResponseAsync(request, response, ticket);
        }

        protected override Task<bool> HandleUnauthorizedAsync(ChallengeContext context) {
            // Extract the OpenID Connect request from the ASP.NET context.
            // If it cannot be found or doesn't correspond to a userinfo request,
            // return false to allow the other middleware to process the challenge.
            var request = Context.GetOpenIdConnectRequest();
            if (request == null || !request.IsUserinfoRequest()) {
                return Task.FromResult(false);
            }

            Response.StatusCode = 401;
            Response.Headers.Append(HeaderNames.WWWAuthenticate, "error=" + OpenIdConnectConstants.Errors.InvalidGrant);

            // Note: due to a bug in AuthenticationHandler.HandleAutomaticChallengeIfNeeded,
            // false must be returned to prevent the other middleware from applying a challenge.
            return Task.FromResult(false);
        }

        private async Task<bool> SendNativePageAsync(OpenIdConnectResponse response) {
            using (var buffer = new MemoryStream())
            using (var writer = new StreamWriter(buffer)) {
                foreach (var parameter in response) {
                    var value = parameter.Value as JValue;
                    if (value == null) {
                        Logger.LogWarning("A parameter whose type was incompatible was ignored " +
                                          "and excluded from the response: '{Parameter}'.", parameter.Key);

                        continue;
                    }

                    writer.WriteLine("{0}: {1}", parameter.Key, (string) value);
                }

                writer.Flush();

                if (!string.IsNullOrEmpty(response.Error)) {
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

        private async Task<bool> SendPayloadAsync(OpenIdConnectResponse response) {
            using (var buffer = new MemoryStream())
            using (var writer = new JsonTextWriter(new StreamWriter(buffer))) {
                var serializer = JsonSerializer.CreateDefault();
                serializer.Serialize(writer, response);

                writer.Flush();

                if (!string.IsNullOrEmpty(response.Error)) {
                    Response.StatusCode = 400;
                }

                Response.ContentLength = buffer.Length;
                Response.ContentType = "application/json;charset=UTF-8";

                Response.Headers[HeaderNames.CacheControl] = "no-cache";
                Response.Headers[HeaderNames.Pragma] = "no-cache";
                Response.Headers[HeaderNames.Expires] = "-1";

                buffer.Seek(offset: 0, loc: SeekOrigin.Begin);
                await buffer.CopyToAsync(Response.Body, 4096, Context.RequestAborted);

                // Return true to stop processing the request.
                return true;
            }
        }

        private class Appender {
            private readonly char _delimiter;
            private readonly StringBuilder _sb;
            private bool _hasDelimiter;

            public Appender(string value, char delimiter) {
                _sb = new StringBuilder(value);
                _delimiter = delimiter;
                _hasDelimiter = value.IndexOf(delimiter) != -1;
            }

            public Appender Append(string name, string value) {
                _sb.Append(_hasDelimiter ? '&' : _delimiter)
                   .Append(Uri.EscapeDataString(name))
                   .Append('=')
                   .Append(Uri.EscapeDataString(value));
                _hasDelimiter = true;
                return this;
            }

            public override string ToString() {
                return _sb.ToString();
            }
        }
    }
}
