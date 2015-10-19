/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.Globalization;
using System.IdentityModel.Tokens;
using System.IO;
using System.Net;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Protocols;
using Microsoft.Owin.Infrastructure;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Owin.Security.OpenIdConnect.Extensions;

namespace Owin.Security.OpenIdConnect.Server {
    internal partial class OpenIdConnectServerHandler : AuthenticationHandler<OpenIdConnectServerOptions> {
        // Implementing AuthenticateCoreAsync allows the inner application
        // to retrieve the identity extracted from the optional id_token_hint.
        protected override async Task<AuthenticationTicket> AuthenticateCoreAsync() {
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

            // Try to retrieve the current OpenID Connect request from the OWIN context.
            // If the request cannot be found, this means that this middleware was configured
            // to use the automatic authentication mode and that AuthenticateCoreAsync
            // was invoked before Invoke*EndpointAsync: in this case, the OpenID Connect
            // request is directly extracted from the query string or the request form.
            var request = Context.GetOpenIdConnectRequest();
            if (request == null) {
                if (string.Equals(Request.Method, "GET", StringComparison.OrdinalIgnoreCase)) {
                    request = new OpenIdConnectMessage(Request.Query);
                }

                else if (string.Equals(Request.Method, "POST", StringComparison.OrdinalIgnoreCase)) {
                    if (string.IsNullOrEmpty(Request.ContentType)) {
                        return null;
                    }

                    else if (!Request.ContentType.StartsWith("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase)) {
                        return null;
                    }

                    request = new OpenIdConnectMessage(await Request.ReadFormAsync());
                }
            }

            // Missing or invalid requests are ignored in AuthenticateCoreAsync:
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
                    Options.Logger.WriteVerbose("Invalid id_token_hint");

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
                    var header = Request.Headers.Get("Authorization");
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
                    Options.Logger.WriteVerbose("Invalid access_token");

                    return null;
                }

                if (!ticket.Properties.ExpiresUtc.HasValue ||
                     ticket.Properties.ExpiresUtc < Options.SystemClock.UtcNow) {
                    Options.Logger.WriteVerbose("Expired access_token");

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

            // Reject non-HTTPS requests handled by the OpenID Connect server middleware if AllowInsecureHttp is not set to true.
            if (!Options.AllowInsecureHttp && string.Equals(Request.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase)) {
                Options.Logger.WriteWarning("The HTTP request was rejected because AllowInsecureHttp was false.");

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

        protected override async Task InitializeCoreAsync() {
            Response.OnSendingHeaders(state => {
                var handler = (OpenIdConnectServerHandler) state;

                // Add a unique key indicating response headers have been sent.
                handler.Context.Environment["app.HeadersSent"] = true;
            }, this);

            await base.InitializeCoreAsync();
        }

        /// <remarks>
        /// Authentication handlers cannot reliabily write to the response stream
        /// from ApplyResponseGrantAsync or ApplyResponseChallengeAsync because these methods
        /// are susceptible to be invoked from AuthenticationHandler.OnSendingHeaderCallback
        /// where calling Write or WriteAsync on the response stream may result in a deadlock
        /// on hosts using streamed responses. To work around this limitation, OpenIdConnectServerHandler
        /// doesn't implement ApplyResponseGrantAsync but TeardownCoreAsync,
        /// which is never called by AuthenticationHandler.OnSendingHeaderCallback.
        /// In theory, this would prevent OpenIdConnectServerHandler from both applying
        /// the response grant and allowing the next middleware in the pipeline to alter
        /// the response stream but in practice, the OpenIdConnectServerHandler is assumed to be
        /// the only middleware allowed to write to the response stream when a response grant has been applied.
        /// </remarks>
        protected override async Task TeardownCoreAsync() {
            // Stop processing the request if no OpenID Connect
            // message has been found in the current context.
            var request = Context.GetOpenIdConnectRequest();
            if (request == null) {
                return;
            }

            // Apply the default request processing if no OpenID Connect
            // response has been forged by the inner application.
            var response = Context.GetOpenIdConnectResponse();
            if (response == null) {
                if (await HandleAuthorizationResponseAsync()) {
                    return;
                }

                await HandleLogoutResponseAsync();
                return;
            }

            // Successful authorization responses are directly applied by
            // HandleAuthorizationResponseAsync: only error responses should be handled at this stage.
            if (string.IsNullOrEmpty(response.Error)) {
                return;
            }

            await SendErrorRedirectAsync(request, response);
        }

        protected override async Task ApplyResponseChallengeAsync() {
            var context = new MatchEndpointContext(Context, Options);

            if (Options.ProfileEndpointPath.HasValue &&
                Options.ProfileEndpointPath == Request.Path) {
                context.MatchesProfileEndpoint();
            }

            await Options.Provider.MatchEndpoint(context);

            if (!context.IsProfileEndpoint) {
                return;
            }

            Response.StatusCode = 401;
            Response.Headers.Set("WWW-Authenticate", "error=" + OpenIdConnectConstants.Errors.InvalidGrant);
        }

        private async Task<bool> HandleAuthorizationResponseAsync() {
            // request may be null when no authorization request has been received
            // or has been already handled by InvokeAuthorizationEndpointAsync.
            var request = Context.GetOpenIdConnectRequest();
            if (request == null) {
                return false;
            }

            // Stop processing the request if there's no response grant that matches
            // the authentication type associated with this middleware instance
            // or if the response status code doesn't indicate a successful response.
            var context = Helper.LookupSignIn(Options.AuthenticationType);
            if (context == null || Response.StatusCode != 200) {
                return false;
            }

            if (Context.Environment.ContainsKey("app.HeadersSent")) {
                Options.Logger.WriteCritical(
                    "OpenIdConnectServerHandler.TeardownCoreAsync cannot be called when " +
                    "the response headers have already been sent back to the user agent. " +
                    "Make sure the response body has not been altered and that no middleware " +
                    "has attempted to write to the response stream during this request.");

                return true;
            }

            if (!context.Principal.HasClaim(claim => claim.Type == ClaimTypes.NameIdentifier) &&
                !context.Principal.HasClaim(claim => claim.Type == JwtRegisteredClaimNames.Sub)) {
                Options.Logger.WriteError("The returned identity doesn't contain the mandatory ClaimTypes.NameIdentifier claim.");

                await SendNativeErrorPageAsync(new OpenIdConnectMessage {
                    Error = OpenIdConnectConstants.Errors.ServerError,
                    ErrorDescription = "no ClaimTypes.NameIdentifier or sub claim found"
                });

                return true;
            }

            // redirect_uri is added to the response message since it's not a mandatory parameter
            // in OAuth 2.0 and can be set or replaced from the ValidateClientRedirectUri event.
            var response = new OpenIdConnectMessage {
                RedirectUri = request.RedirectUri,
                State = request.State
            };

            // Associate client_id with all subsequent tickets.
            context.Properties.Dictionary[OpenIdConnectConstants.Extra.ClientId] = request.ClientId;

            if (!string.IsNullOrEmpty(request.Nonce)) {
                // Keep the original nonce parameter for later comparison.
                context.Properties.Dictionary[OpenIdConnectConstants.Extra.Nonce] = request.Nonce;
            }

            if (!string.IsNullOrEmpty(request.RedirectUri)) {
                // Keep original the original redirect_uri for later comparison.
                context.Properties.Dictionary[OpenIdConnectConstants.Extra.RedirectUri] = request.RedirectUri;
            }

            if (!string.IsNullOrEmpty(request.Resource)) {
                // Keep the original resource parameter for later comparison.
                context.Properties.Dictionary[OpenIdConnectConstants.Extra.Resource] = request.Resource;
            }

            if (!string.IsNullOrEmpty(request.Scope)) {
                // Keep the original scope parameter for later comparison.
                context.Properties.Dictionary[OpenIdConnectConstants.Extra.Scope] = request.Scope;
            }

            // Determine whether an authorization code should be returned
            // and invoke CreateAuthorizationCodeAsync if necessary.
            if (request.ContainsResponseType(OpenIdConnectConstants.ResponseTypes.Code)) {
                // Make sure to create a copy of the authentication properties
                // to avoid modifying the properties set on the original ticket.
                var properties = context.Properties.Copy();

                // properties.IssuedUtc and properties.ExpiresUtc are always
                // explicitly set to null to avoid aligning the expiration date
                // of the authorization code with the lifetime of the other tokens.
                properties.IssuedUtc = properties.ExpiresUtc = null;

                response.Code = await CreateAuthorizationCodeAsync(context.Identity, properties, request, response);

                // Ensure that an authorization code is issued to avoid returning an invalid response.
                // See http://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#Combinations
                if (string.IsNullOrEmpty(response.Code)) {
                    Options.Logger.WriteError("CreateAuthorizationCodeAsync returned no authorization code");

                    await SendNativeErrorPageAsync(new OpenIdConnectMessage {
                        Error = OpenIdConnectConstants.Errors.ServerError,
                        ErrorDescription = "no valid authorization code was issued"
                    });

                    return true;
                }
            }

            // Determine whether an access token should be returned
            // and invoke CreateAccessTokenAsync if necessary.
            if (request.ContainsResponseType(OpenIdConnectConstants.ResponseTypes.Token)) {
                // Make sure to create a copy of the authentication properties
                // to avoid modifying the properties set on the original ticket.
                var properties = context.Properties.Copy();

                response.TokenType = OpenIdConnectConstants.TokenTypes.Bearer;
                response.AccessToken = await CreateAccessTokenAsync(context.Identity, properties, request, response);

                // Ensure that an access token is issued to avoid returning an invalid response.
                // See http://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#Combinations
                if (string.IsNullOrEmpty(response.AccessToken)) {
                    Options.Logger.WriteError("CreateAccessTokenAsync returned no access token.");

                    await SendNativeErrorPageAsync(new OpenIdConnectMessage {
                        Error = OpenIdConnectConstants.Errors.ServerError,
                        ErrorDescription = "no valid access token was issued"
                    });

                    return true;
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
            if (request.ContainsResponseType(OpenIdConnectConstants.ResponseTypes.IdToken)) {
                // Make sure to create a copy of the authentication properties
                // to avoid modifying the properties set on the original ticket.
                var properties = context.Properties.Copy();

                response.IdToken = await CreateIdentityTokenAsync(context.Identity, properties, request, response);

                // Ensure that an identity token is issued to avoid returning an invalid response.
                // See http://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#Combinations
                if (string.IsNullOrEmpty(response.IdToken)) {
                    Options.Logger.WriteError("CreateIdentityTokenAsync returned no identity token.");

                    await SendNativeErrorPageAsync(new OpenIdConnectMessage {
                        Error = OpenIdConnectConstants.Errors.ServerError,
                        ErrorDescription = "no valid identity token was issued"
                    });

                    return true;
                }
            }

            // Remove the OpenID Connect request from the cache.
            var identifier = request.GetUniqueIdentifier();
            if (!string.IsNullOrEmpty(identifier)) {
                Options.Cache.Remove(identifier);
            }

            var ticket = new AuthenticationTicket(context.Identity, context.Properties);

            var notification = new AuthorizationEndpointResponseContext(Context, Options, ticket, request, response);
            await Options.Provider.AuthorizationEndpointResponse(notification);

            if (notification.HandledResponse) {
                return true;
            }

            return await ApplyAuthorizationResponseAsync(request, response);
        }

        private async Task<bool> HandleLogoutResponseAsync() {
            // request may be null when no logout request has been received
            // or has been already handled by InvokeLogoutEndpointAsync.
            var request = Context.GetOpenIdConnectRequest();
            if (request == null) {
                return false;
            }
            
            // Stop processing the request if there's no signout context that matches
            // the authentication type associated with this middleware instance
            // or if the response status code doesn't indicate a successful response.
            var context = Helper.LookupSignOut(Options.AuthenticationType, Options.AuthenticationMode);
            if (context == null || Response.StatusCode != 200) {
                return false;
            }

            if (Context.Environment.ContainsKey("app.HeadersSent")) {
                Options.Logger.WriteCritical(
                    "OpenIdConnectServerHandler.TeardownCoreAsync cannot be called when " +
                    "the response headers have already been sent back to the user agent. " +
                    "Make sure the response body has not been altered and that no middleware " +
                    "has attempted to write to the response stream during this request.");
                return false;
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
                return true;
            }

            // Stop processing the request if no explicit
            // post_logout_redirect_uri has been provided.
            if (string.IsNullOrEmpty(response.PostLogoutRedirectUri)) {
                return true;
            }

            var location = response.PostLogoutRedirectUri;

            foreach (var parameter in response.Parameters) {
                // Don't include post_logout_redirect_uri in the query string.
                if (string.Equals(parameter.Key, OpenIdConnectParameterNames.PostLogoutRedirectUri, StringComparison.Ordinal)) {
                    continue;
                }

                location = WebUtilities.AddQueryString(location, parameter.Key, parameter.Value);
            }

            Response.Redirect(location);

            return true;
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
                    writer.WriteLine("<form name='form' method='post' action='" + WebUtility.HtmlEncode(response.RedirectUri) + "'>");

                    foreach (var parameter in response.Parameters) {
                        // Don't include redirect_uri in the form.
                        if (string.Equals(parameter.Key, OpenIdConnectParameterNames.RedirectUri, StringComparison.Ordinal)) {
                            continue;
                        }

                        var key = WebUtility.HtmlEncode(parameter.Key);
                        var value = WebUtility.HtmlEncode(parameter.Value);

                        writer.WriteLine("<input type='hidden' name='" + key + "' value='" + value + "' />");
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
                    await buffer.CopyToAsync(Response.Body, 4096, Request.CallCancelled);

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

                    location = WebUtilities.AddQueryString(location, parameter.Key, parameter.Value);
                }

                Response.Redirect(location);
                return true;
            }

            return false;
        }

        private async Task<bool> SendErrorRedirectAsync(OpenIdConnectMessage request, OpenIdConnectMessage response) {
            // Remove the authorization request from the OWIN context to inform
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

                Response.Headers.Set("Cache-Control", "no-cache");
                Response.Headers.Set("Pragma", "no-cache");
                Response.Headers.Set("Expires", "-1");

                buffer.Seek(offset: 0, loc: SeekOrigin.Begin);
                await buffer.CopyToAsync(Response.Body, 4096, Request.CallCancelled);
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

                Response.Headers.Set("Cache-Control", "no-cache");
                Response.Headers.Set("Pragma", "no-cache");
                Response.Headers.Set("Expires", "-1");

                buffer.Seek(offset: 0, loc: SeekOrigin.Begin);
                await buffer.CopyToAsync(Response.Body, 4096, Request.CallCancelled);
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
