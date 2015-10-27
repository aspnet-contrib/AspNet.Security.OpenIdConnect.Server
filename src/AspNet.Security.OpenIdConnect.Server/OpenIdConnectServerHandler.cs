/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.Globalization;
using System.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Extensions;
using Microsoft.AspNet.Authentication;
using Microsoft.AspNet.Builder;
using Microsoft.AspNet.Http.Authentication;
using Microsoft.AspNet.Http.Features.Authentication;
using Microsoft.AspNet.WebUtilities;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.Net.Http.Headers;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace AspNet.Security.OpenIdConnect.Server {
    internal partial class OpenIdConnectServerHandler : AuthenticationHandler<OpenIdConnectServerOptions> {
        protected override async Task<AuthenticationTicket> HandleAuthenticateAsync() {
            var notification = new MatchEndpointContext(Context, Options);

            if (Options.AuthorizationEndpointPath.HasValue &&
                Options.AuthorizationEndpointPath == Request.Path) {
                notification.MatchesAuthorizationEndpoint();
            }

            else if (Options.LogoutEndpointPath.HasValue &&
                     Options.LogoutEndpointPath == Request.Path) {
                notification.MatchesLogoutEndpoint();
            }

            else if (Options.ProfileEndpointPath.HasValue &&
                     Options.ProfileEndpointPath == Request.Path) {
                notification.MatchesProfileEndpoint();
            }

            await Options.Provider.MatchEndpoint(notification);
            
            if (!notification.IsAuthorizationEndpoint &&
                !notification.IsLogoutEndpoint &&
                !notification.IsProfileEndpoint) {
                return null;
            }

            // Try to retrieve the current OpenID Connect request from the ASP.NET context.
            // If the request cannot be found, this means that this middleware was configured
            // to use the automatic authentication mode and that HandleAuthenticateAsync
            // was invoked before Invoke*EndpointAsync: in this case, the OpenID Connect
            // request is directly extracted from the query string or the request form.
            var request = Context.GetOpenIdConnectRequest();
            if (request == null) {
                if (string.Equals(Request.Method, "GET", StringComparison.OrdinalIgnoreCase)) {
                    request = new OpenIdConnectMessage(Request.Query.ToDictionary());
                }

                else if (string.Equals(Request.Method, "POST", StringComparison.OrdinalIgnoreCase)) {
                    if (string.IsNullOrEmpty(Request.ContentType)) {
                        return null;
                    }

                    else if (!Request.ContentType.StartsWith("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase)) {
                        return null;
                    }

                    var form = await Request.ReadFormAsync(Context.RequestAborted);

                    request = new OpenIdConnectMessage(form.ToDictionary());
                }
            }

            // Missing or invalid requests are ignored in HandleAuthenticateAsync:
            // in this case, null is always returned to indicate authentication failed.
            if (request == null) {
                return null;
            }

            if (notification.IsAuthorizationEndpoint || notification.IsLogoutEndpoint) {
                if (string.IsNullOrEmpty(request.IdTokenHint)) {
                    return null;
                }

                var ticket = await ReceiveIdentityTokenAsync(request.IdTokenHint, request);
                if (ticket == null) {
                    Logger.LogVerbose("Invalid id_token_hint");

                    return null;
                }

                // Tickets are returned even if they
                // are considered invalid (e.g expired).
                return ticket;
            }

            else if (notification.IsProfileEndpoint) {
                string token;
                if (!string.IsNullOrEmpty(request.AccessToken)) {
                    token = request.AccessToken;
                }

                else {
                    string header = Request.Headers[HeaderNames.Authorization];
                    if (string.IsNullOrEmpty(header)) {
                        return null;
                    }

                    if (!header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)) {
                        return null;
                    }

                    token = header.Substring("Bearer ".Length);
                    if (string.IsNullOrWhiteSpace(token)) {
                        return null;
                    }
                }

                var ticket = await ReceiveAccessTokenAsync(token, request);
                if (ticket == null) {
                    Logger.LogVerbose("Invalid access_token");

                    return null;
                }

                if (!ticket.Properties.ExpiresUtc.HasValue ||
                     ticket.Properties.ExpiresUtc < Options.SystemClock.UtcNow) {
                    Logger.LogVerbose("Expired access_token");

                    return null;
                }

                return ticket;
            }

            return null;
        }

        public override async Task<bool> InvokeAsync() {
            var notification = new MatchEndpointContext(Context, Options);

            if (Options.AuthorizationEndpointPath.HasValue &&
                Options.AuthorizationEndpointPath == Request.Path) {
                notification.MatchesAuthorizationEndpoint();
            }

            else if (Options.TokenEndpointPath.HasValue &&
                     Options.TokenEndpointPath == Request.Path) {
                notification.MatchesTokenEndpoint();
            }

            else if (Options.ValidationEndpointPath.HasValue &&
                     Options.ValidationEndpointPath == Request.Path) {
                notification.MatchesValidationEndpoint();
            }

            else if (Options.ProfileEndpointPath.HasValue &&
                     Options.ProfileEndpointPath == Request.Path) {
                notification.MatchesProfileEndpoint();
            }

            else if (Options.LogoutEndpointPath.HasValue &&
                     Options.LogoutEndpointPath == Request.Path) {
                notification.MatchesLogoutEndpoint();
            }

            else if (Options.ConfigurationEndpointPath.HasValue &&
                     Options.ConfigurationEndpointPath == Request.Path) {
                notification.MatchesConfigurationEndpoint();
            }

            else if (Options.CryptographyEndpointPath.HasValue &&
                     Options.CryptographyEndpointPath == Request.Path) {
                notification.MatchesCryptographyEndpoint();
            }

            await Options.Provider.MatchEndpoint(notification);

            if (notification.HandledResponse) {
                return true;
            }

            else if (notification.Skipped) {
                return false;
            }

            // Reject non-HTTPS requests handled by the OpenID Connect
            // server middleware if AllowInsecureHttp is not set to true.
            if (!Options.AllowInsecureHttp && !Request.IsHttps) {
                Logger.LogWarning("The HTTP request was rejected because AllowInsecureHttp was false.");

                if (notification.IsAuthorizationEndpoint || notification.IsLogoutEndpoint) {
                    // Return the native error page for endpoints involving the user participation.
                    await SendNativeErrorPageAsync(new OpenIdConnectMessage {
                        Error = OpenIdConnectConstants.Errors.InvalidRequest,
                        ErrorDescription = "This server only accepts HTTPS requests."
                    });

                    return true;
                }

                else if (notification.IsTokenEndpoint || notification.IsProfileEndpoint ||
                         notification.IsValidationEndpoint || notification.IsConfigurationEndpoint ||
                         notification.IsCryptographyEndpoint) {
                    // Return a JSON error for endpoints that don't involve the user participation.
                    await SendErrorPayloadAsync(new OpenIdConnectMessage {
                        Error = OpenIdConnectConstants.Errors.InvalidRequest,
                        ErrorDescription = "This server only accepts HTTPS requests."
                    });

                    return true;
                }
            }

            if (notification.IsAuthorizationEndpoint) {
                return await InvokeAuthorizationEndpointAsync();
            }

            else if (notification.IsLogoutEndpoint) {
                return await InvokeLogoutEndpointAsync();
            }

            else if (notification.IsTokenEndpoint) {
                await InvokeTokenEndpointAsync();
                return true;
            }

            else if (notification.IsValidationEndpoint) {
                await InvokeValidationEndpointAsync();
                return true;
            }

            else if (notification.IsProfileEndpoint) {
                return await InvokeProfileEndpointAsync();
            }

            else if (notification.IsConfigurationEndpoint) {
                await InvokeConfigurationEndpointAsync();
                return true;
            }

            else if (notification.IsCryptographyEndpoint) {
                await InvokeCryptographyEndpointAsync();
                return true;
            }

            return false;
        }

        protected override async Task HandleSignInAsync(SignInContext context) {
            // request may be null when no authorization request has been received
            // or has been already handled by InvokeAuthorizationEndpointAsync.
            var request = Context.GetOpenIdConnectRequest();
            if (request == null) {
                return;
            }

            // Stop processing the request if there's no response grant that matches
            // the authentication type associated with this middleware instance
            // or if the response status code doesn't indicate a successful response.
            if (context == null || Response.StatusCode != 200) {
                return;
            }

            if (Response.HasStarted) {
                Logger.LogCritical(
                    "OpenIdConnectServerHandler.TeardownCoreAsync cannot be called when " +
                    "the response headers have already been sent back to the user agent. " +
                    "Make sure the response body has not been altered and that no middleware " +
                    "has attempted to write to the response stream during this request.");
                return;
            }

            if (!context.Principal.HasClaim(claim => claim.Type == ClaimTypes.NameIdentifier) &&
                !context.Principal.HasClaim(claim => claim.Type == JwtRegisteredClaimNames.Sub)) {
                Logger.LogError("The returned identity doesn't contain the mandatory ClaimTypes.NameIdentifier claim.");

                await SendNativeErrorPageAsync(new OpenIdConnectMessage {
                    Error = OpenIdConnectConstants.Errors.ServerError,
                    ErrorDescription = "no ClaimTypes.NameIdentifier or sub claim found"
                });

                return;
            }

            // redirect_uri is added to the response message since it's not a mandatory parameter
            // in OAuth 2.0 and can be set or replaced from the ValidateClientRedirectUri event.
            var response = new OpenIdConnectMessage {
                RedirectUri = request.RedirectUri,
                State = request.State
            };

            // Associate client_id with all subsequent tickets.
            context.Properties[OpenIdConnectConstants.Extra.ClientId] = request.ClientId;

            if (!string.IsNullOrEmpty(request.Nonce)) {
                // Keep the original nonce parameter for later comparison.
                context.Properties[OpenIdConnectConstants.Extra.Nonce] = request.Nonce;
            }

            if (!string.IsNullOrEmpty(request.RedirectUri)) {
                // Keep the original redirect_uri parameter for later comparison.
                context.Properties[OpenIdConnectConstants.Extra.RedirectUri] = request.RedirectUri;
            }

            // Note: the application is allowed to specify a different "resource"
            // parameter when calling AuthenticationManager.SignInAsync: in this case,
            // don't replace the "resource" property stored in the authentication ticket.
            if (!string.IsNullOrEmpty(request.Resource) &&
                !context.Properties.ContainsKey(OpenIdConnectConstants.Extra.Resource)) {
                // Keep the original resource parameter for later comparison.
                context.Properties[OpenIdConnectConstants.Extra.Resource] = request.Resource;
            }

            // Note: the application is allowed to specify a different "scope"
            // parameter when calling AuthenticationManager.SignInAsync: in this case,
            // don't replace the "scope" property stored in the authentication ticket.
            if (!string.IsNullOrEmpty(request.Scope) &&
                !context.Properties.ContainsKey(OpenIdConnectConstants.Extra.Scope)) {
                // Keep the original scope parameter for later comparison.
                context.Properties[OpenIdConnectConstants.Extra.Scope] = request.Scope;
            }

            // Determine whether an authorization code should be returned
            // and invoke CreateAuthorizationCodeAsync if necessary.
            if (request.ContainsResponseType(OpenIdConnectConstants.ResponseTypes.Code)) {
                // Make sure to create a copy of the authentication properties
                // to avoid modifying the properties set on the original ticket.
                var properties = new AuthenticationProperties(context.Properties).Copy();

                // properties.IssuedUtc and properties.ExpiresUtc are always
                // explicitly set to null to avoid aligning the expiration date
                // of the authorization code with the lifetime of the other tokens.
                properties.IssuedUtc = properties.ExpiresUtc = null;

                response.Code = await CreateAuthorizationCodeAsync(context.Principal, properties, request, response);

                // Ensure that an authorization code is issued to avoid returning an invalid response.
                // See http://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#Combinations
                if (string.IsNullOrEmpty(response.Code)) {
                    Logger.LogError("CreateAuthorizationCodeAsync returned no authorization code");

                    await SendNativeErrorPageAsync(new OpenIdConnectMessage {
                        Error = OpenIdConnectConstants.Errors.ServerError,
                        ErrorDescription = "no valid authorization code was issued"
                    });

                    return;
                }
            }

            // Determine whether an access token should be returned
            // and invoke CreateAccessTokenAsync if necessary.
            if (request.ContainsResponseType(OpenIdConnectConstants.ResponseTypes.Token)) {
                // Make sure to create a copy of the authentication properties
                // to avoid modifying the properties set on the original ticket.
                var properties = new AuthenticationProperties(context.Properties).Copy();

                // Note: when the "resource" parameter added to the OpenID Connect response
                // is identical to the request parameter, keeping it is not necessary.
                var resource = properties.GetProperty(OpenIdConnectConstants.Extra.Resource);
                if (!string.Equals(request.Resource, resource, StringComparison.Ordinal)) {
                    response.Resource = resource;
                }

                // Note: when the "scope" parameter added to the OpenID Connect response
                // is identical to the request parameter, keeping it is not necessary.
                var scope = properties.GetProperty(OpenIdConnectConstants.Extra.Scope);
                if (!string.Equals(request.Scope, scope, StringComparison.Ordinal)) {
                    response.Scope = scope;
                }

                response.TokenType = OpenIdConnectConstants.TokenTypes.Bearer;
                response.AccessToken = await CreateAccessTokenAsync(context.Principal, properties, request, response);

                // Ensure that an access token is issued to avoid returning an invalid response.
                // See http://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#Combinations
                if (string.IsNullOrEmpty(response.AccessToken)) {
                    Logger.LogError("CreateAccessTokenAsync returned no access token.");

                    await SendNativeErrorPageAsync(new OpenIdConnectMessage {
                        Error = OpenIdConnectConstants.Errors.ServerError,
                        ErrorDescription = "no valid access token was issued"
                    });

                    return;
                }

                // properties.ExpiresUtc is automatically set by CreateAccessTokenAsync but the end user
                // is free to set a null value directly in the CreateAccessToken event.
                if (properties.ExpiresUtc.HasValue && properties.ExpiresUtc > Options.SystemClock.UtcNow) {
                    var lifetime = properties.ExpiresUtc.Value - Options.SystemClock.UtcNow;
                    var expiration = (long) (lifetime.TotalSeconds + .5);

                    response.ExpiresIn = expiration.ToString(CultureInfo.InvariantCulture);
                }
            }

            // Determine whether an identity token should be returned
            // and invoke CreateIdentityTokenAsync if necessary.
            // Note: the identity token MUST be created after the authorization code
            // and the access token to create appropriate at_hash and c_hash claims.
            if (request.ContainsResponseType(OpenIdConnectConstants.ResponseTypes.IdToken)) {
                // Make sure to create a copy of the authentication properties
                // to avoid modifying the properties set on the original ticket.
                var properties = new AuthenticationProperties(context.Properties).Copy();

                response.IdToken = await CreateIdentityTokenAsync(context.Principal, properties, request, response);

                // Ensure that an identity token is issued to avoid returning an invalid response.
                // See http://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#Combinations
                if (string.IsNullOrEmpty(response.IdToken)) {
                    Logger.LogError("CreateIdentityTokenAsync returned no identity token.");

                    await SendNativeErrorPageAsync(new OpenIdConnectMessage {
                        Error = OpenIdConnectConstants.Errors.ServerError,
                        ErrorDescription = "no valid identity token was issued",
                    });

                    return;
                }
            }

            // Remove the OpenID Connect request from the distributed cache.
            var identifier = request.GetUniqueIdentifier();
            if (!string.IsNullOrEmpty(identifier)) {
                await Options.Cache.RemoveAsync(identifier);
            }

            var ticket = new AuthenticationTicket(context.Principal,
                new AuthenticationProperties(context.Properties),
                context.AuthenticationScheme);

            var notification = new AuthorizationEndpointResponseContext(Context, Options, ticket, request, response);
            await Options.Provider.AuthorizationEndpointResponse(notification);

            if (notification.HandledResponse) {
                return;
            }

            await ApplyAuthorizationResponseAsync(request, response);
        }

        protected override async Task HandleSignOutAsync(SignOutContext context) {
            // request may be null when no logout request has been received
            // or has been already handled by InvokeLogoutEndpointAsync.
            var request = Context.GetOpenIdConnectRequest();
            if (request == null) {
                return;
            }

            // Stop processing the request if there's no signout context that matches
            // the authentication type associated with this middleware instance
            // or if the response status code doesn't indicate a successful response.
            if (context == null || Response.StatusCode != 200) {
                return;
            }

            if (Response.HasStarted) {
                Logger.LogCritical(
                    "OpenIdConnectServerHandler.TeardownCoreAsync cannot be called when " +
                    "the response headers have already been sent back to the user agent. " +
                    "Make sure the response body has not been altered and that no middleware " +
                    "has attempted to write to the response stream during this request.");
                return;
            }

            // post_logout_redirect_uri is added to the response message since it can be
            // set or replaced from the ValidateClientLogoutRedirectUri event.
            var response = new OpenIdConnectMessage {
                PostLogoutRedirectUri = request.PostLogoutRedirectUri,
                State = request.State
            };

            var notification = new LogoutEndpointResponseContext(Context, Options, request, response);
            await Options.Provider.LogoutEndpointResponse(notification);

            if (notification.HandledResponse) {
                return;
            }

            // Stop processing the request if no explicit
            // post_logout_redirect_uri has been provided.
            if (string.IsNullOrEmpty(response.PostLogoutRedirectUri)) {
                return;
            }

            var location = response.PostLogoutRedirectUri;

            foreach (var parameter in response.Parameters) {
                // Don't include post_logout_redirect_uri in the query string.
                if (string.Equals(parameter.Key, OpenIdConnectParameterNames.PostLogoutRedirectUri, StringComparison.Ordinal)) {
                    continue;
                }

                location = QueryHelpers.AddQueryString(location, parameter.Key, parameter.Value);
            }

            Response.Redirect(location);
        }

        protected override async Task<bool> HandleUnauthorizedAsync(ChallengeContext context) {
            var notification = new MatchEndpointContext(Context, Options);

            if (Options.ProfileEndpointPath.HasValue &&
                Options.ProfileEndpointPath == Request.Path) {
                notification.MatchesProfileEndpoint();
            }

            await Options.Provider.MatchEndpoint(notification);

            // Return true to indicate to the authentication pipeline that
            // the 401 response shouldn't be handled by the other middleware.
            if (!notification.IsProfileEndpoint) {
                return true;
            }

            Response.StatusCode = 401;
            Response.Headers[HeaderNames.WWWAuthenticate] = "error=" + OpenIdConnectConstants.Errors.InvalidGrant;

            return false;
        }

        protected override async Task FinishResponseAsync() {
            // Stop processing the request if no OpenID Connect
            // message has been found in the current context.
            var request = Context.GetOpenIdConnectRequest();
            if (request == null) {
                return;
            }

            // Don't apply any modification to the response if no OpenID Connect
            // message has been explicitly created by the inner application.
            var response = Context.GetOpenIdConnectResponse();
            if (response == null) {
                return;
            }

            // Successful authorization responses are directly applied by
            // HandleSignInAsync: only error responses should be handled at this stage.
            if (string.IsNullOrEmpty(response.Error)) {
                return;
            }

            await SendErrorRedirectAsync(request, response);
        }

        private async Task<bool> ApplyAuthorizationResponseAsync(OpenIdConnectMessage request, OpenIdConnectMessage response) {
            if (request.IsFormPostResponseMode()) {
                using (var buffer = new MemoryStream())
                using (var writer = new StreamWriter(buffer)) {
                    writer.WriteLine("<!doctype html>");
                    writer.WriteLine("<html>");
                    writer.WriteLine("<body>");

                    // While the redirect_uri parameter should be guarded against unknown values
                    // by IOpenIdConnectServerProvider.ValidateClientRedirectUri,
                    // it's still safer to encode it to avoid cross-site scripting attacks
                    // if the authorization server has a relaxed policy concerning redirect URIs.
                    writer.WriteLine("<form name='form' method='post' action='" + Options.HtmlEncoder.HtmlEncode(response.RedirectUri) + "'>");

                    foreach (var parameter in response.Parameters) {
                        // Don't include redirect_uri in the form.
                        if (string.Equals(parameter.Key, OpenIdConnectParameterNames.RedirectUri, StringComparison.Ordinal)) {
                            continue;
                        }

                        var name = Options.HtmlEncoder.HtmlEncode(parameter.Key);
                        var value = Options.HtmlEncoder.HtmlEncode(parameter.Value);

                        writer.WriteLine("<input type='hidden' name='" + name + "' value='" + value + "' />");
                    }

                    writer.WriteLine("<noscript>Click here to finish the authorization process: <input type='submit' /></noscript>");
                    writer.WriteLine("</form>");
                    writer.WriteLine("<script>document.form.submit();</script>");
                    writer.WriteLine("</body>");
                    writer.WriteLine("</html>");
                    writer.Flush();

                    Response.ContentLength = buffer.Length;
                    Response.ContentType = "text/html;charset=UTF-8";

                    buffer.Seek(offset: 0, loc: SeekOrigin.Begin);
                    await buffer.CopyToAsync(Response.Body, 4096, Context.RequestAborted);

                    return true;
                }
            }

            else if (request.IsFragmentResponseMode()) {
                var location = response.RedirectUri;
                var appender = new Appender(location, '#');

                foreach (var parameter in response.Parameters) {
                    // Don't include redirect_uri in the fragment.
                    if (string.Equals(parameter.Key, OpenIdConnectParameterNames.RedirectUri, StringComparison.Ordinal)) {
                        continue;
                    }

                    appender.Append(parameter.Key, parameter.Value);
                }

                Response.Redirect(appender.ToString());
                return true;
            }

            else if (request.IsQueryResponseMode()) {
                var location = response.RedirectUri;

                foreach (var parameter in response.Parameters) {
                    // Don't include redirect_uri in the query string.
                    if (string.Equals(parameter.Key, OpenIdConnectParameterNames.RedirectUri, StringComparison.Ordinal)) {
                        continue;
                    }

                    location = QueryHelpers.AddQueryString(location, parameter.Key, parameter.Value);
                }

                Response.Redirect(location);
                return true;
            }

            return false;
        }

        private async Task<bool> SendErrorRedirectAsync(OpenIdConnectMessage request, OpenIdConnectMessage response) {
            // Remove the authorization request from the ASP.NET context to inform
            // TeardownCoreAsync that there's nothing more to handle.
            Context.SetOpenIdConnectRequest(request: null);

            // Use a generic error if none has been explicitly provided.
            if (string.IsNullOrEmpty(response.Error)) {
                response.Error = OpenIdConnectConstants.Errors.InvalidRequest;
            }

            // Directly display an error page if redirect_uri cannot be used.
            if (string.IsNullOrEmpty(response.RedirectUri)) {
                return await SendErrorPageAsync(response);
            }

            // Try redirecting the user agent to the client
            // application or display a default error page.
            if (!await ApplyAuthorizationResponseAsync(request, response)) {
                return await SendErrorPageAsync(response);
            }

            // Stop processing the request.
            return true;
        }

        private async Task<bool> SendErrorPageAsync(OpenIdConnectMessage response) {
            // Use a generic error if none has been explicitly provided.
            if (string.IsNullOrEmpty(response.Error)) {
                response.Error = OpenIdConnectConstants.Errors.InvalidRequest;
            }

            if (Options.ApplicationCanDisplayErrors) {
                Context.SetOpenIdConnectResponse(response);

                // Request is not handled - pass through to application for rendering.
                return false;
            }

            await SendNativeErrorPageAsync(response);

            // Request is always handled when rendering the default error page.
            return true;
        }

        private async Task SendNativeErrorPageAsync(OpenIdConnectMessage response) {
            using (var buffer = new MemoryStream())
            using (var writer = new StreamWriter(buffer)) {
                foreach (var parameter in response.Parameters) {
                    writer.WriteLine("{0}: {1}", parameter.Key, parameter.Value);
                }

                writer.Flush();

                Response.StatusCode = 400;
                Response.ContentLength = buffer.Length;
                Response.ContentType = "text/plain;charset=UTF-8";

                Response.Headers[HeaderNames.CacheControl] = "no-cache";
                Response.Headers[HeaderNames.Pragma] = "no-cache";
                Response.Headers[HeaderNames.Expires] = "-1";

                buffer.Seek(offset: 0, loc: SeekOrigin.Begin);
                await buffer.CopyToAsync(Response.Body, 4096, Context.RequestAborted);
            }
        }

        private async Task SendPayloadAsync(JToken payload) {
            using (var buffer = new MemoryStream())
            using (var writer = new JsonTextWriter(new StreamWriter(buffer))) {
                payload.WriteTo(writer);
                writer.Flush();

                Response.ContentLength = buffer.Length;
                Response.ContentType = "application/json;charset=UTF-8";

                buffer.Seek(offset: 0, loc: SeekOrigin.Begin);
                await buffer.CopyToAsync(Response.Body, 4096, Context.RequestAborted);
            }
        }

        private async Task SendErrorPayloadAsync(OpenIdConnectMessage response) {
            using (var buffer = new MemoryStream())
            using (var writer = new JsonTextWriter(new StreamWriter(buffer))) {
                var payload = new JObject();

                payload.Add(OpenIdConnectConstants.Parameters.Error, response.Error);

                if (!string.IsNullOrEmpty(response.ErrorDescription)) {
                    payload.Add(OpenIdConnectConstants.Parameters.ErrorDescription, response.ErrorDescription);
                }

                if (!string.IsNullOrEmpty(response.ErrorUri)) {
                    payload.Add(OpenIdConnectConstants.Parameters.ErrorUri, response.ErrorUri);
                }

                payload.WriteTo(writer);
                writer.Flush();

                Response.StatusCode = 400;
                Response.ContentLength = buffer.Length;
                Response.ContentType = "application/json;charset=UTF-8";

                Response.Headers[HeaderNames.CacheControl] = "no-cache";
                Response.Headers[HeaderNames.Pragma] = "no-cache";
                Response.Headers[HeaderNames.Expires] = "-1";

                buffer.Seek(offset: 0, loc: SeekOrigin.Begin);
                await buffer.CopyToAsync(Response.Body, 4096, Context.RequestAborted);
            }
        }

        private string GenerateKey(int length) {
            var bytes = new byte[length];
            Options.RandomNumberGenerator.GetBytes(bytes);
            return Base64UrlEncoder.Encode(bytes);
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