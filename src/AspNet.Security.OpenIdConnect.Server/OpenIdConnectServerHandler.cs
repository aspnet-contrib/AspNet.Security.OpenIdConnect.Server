/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Extensions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
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

            else if (Options.ProfileEndpointPath.HasValue &&
                     Options.ProfileEndpointPath == Request.Path) {
                notification.MatchesProfileEndpoint();
            }

            await Options.Provider.MatchEndpoint(notification);
            
            if (!notification.IsAuthorizationEndpoint &&
                !notification.IsLogoutEndpoint &&
                !notification.IsProfileEndpoint) {
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
                    request = new OpenIdConnectMessage(Request.Query.ToDictionary());
                }

                else if (string.Equals(Request.Method, "POST", StringComparison.OrdinalIgnoreCase)) {
                    if (string.IsNullOrEmpty(Request.ContentType)) {
                        return AuthenticateResult.Skip();
                    }

                    else if (!Request.ContentType.StartsWith("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase)) {
                        return AuthenticateResult.Skip();
                    }

                    var form = await Request.ReadFormAsync(Context.RequestAborted);

                    request = new OpenIdConnectMessage(form.ToDictionary());
                }
            }

            // Missing or invalid requests are ignored in HandleAuthenticateAsync:
            // in this case, Skip is used to indicate authentication failed.
            if (request == null) {
                return AuthenticateResult.Skip();
            }

            if (notification.IsAuthorizationEndpoint || notification.IsLogoutEndpoint) {
                if (string.IsNullOrEmpty(request.IdTokenHint)) {
                    return AuthenticateResult.Skip();
                }

                var ticket = await DeserializeIdentityTokenAsync(request.IdTokenHint, request);
                if (ticket == null) {
                    Logger.LogDebug("Invalid id_token_hint");

                    return AuthenticateResult.Skip();
                }

                // Tickets are returned even if they
                // are considered invalid (e.g expired).
                return AuthenticateResult.Success(ticket);
            }

            else if (notification.IsProfileEndpoint) {
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
                    Logger.LogDebug("Invalid access_token");

                    return AuthenticateResult.Skip();
                }

                if (!ticket.Properties.ExpiresUtc.HasValue ||
                     ticket.Properties.ExpiresUtc < Options.SystemClock.UtcNow) {
                    Logger.LogDebug("Expired access_token");

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

            else if (Options.TokenEndpointPath.HasValue &&
                     Options.TokenEndpointPath == Request.Path) {
                notification.MatchesTokenEndpoint();
            }

            else if (Options.IntrospectionEndpointPath.HasValue &&
                     Options.IntrospectionEndpointPath == Request.Path) {
                notification.MatchesIntrospectionEndpoint();
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

            // Reject non-HTTPS requests handled by ASOS if AllowInsecureHttp is not set to true.
            if (!Options.AllowInsecureHttp && !Request.IsHttps) {
                // Return the native error page for endpoints involving the user participation.
                if (notification.IsAuthorizationEndpoint || notification.IsLogoutEndpoint) {
                    Logger.LogWarning("The HTTP request was rejected because AllowInsecureHttp was false.");

                    await SendNativeErrorPageAsync(new OpenIdConnectMessage {
                        Error = OpenIdConnectConstants.Errors.InvalidRequest,
                        ErrorDescription = "This server only accepts HTTPS requests."
                    });

                    return true;
                }

                // Return a JSON error for endpoints that don't involve the user participation.
                else if (notification.IsTokenEndpoint || notification.IsProfileEndpoint ||
                         notification.IsIntrospectionEndpoint || notification.IsConfigurationEndpoint ||
                         notification.IsCryptographyEndpoint) {
                    Logger.LogWarning("The HTTP request was rejected because AllowInsecureHttp was false.");

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

            else if (notification.IsIntrospectionEndpoint) {
                await InvokeIntrospectionEndpointAsync();
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
                    writer.WriteLine("<form name='form' method='post' action='" + Options.HtmlEncoder.Encode(response.RedirectUri) + "'>");

                    foreach (var parameter in response.Parameters) {
                        // Don't include redirect_uri in the form.
                        if (string.Equals(parameter.Key, OpenIdConnectParameterNames.RedirectUri, StringComparison.Ordinal)) {
                            continue;
                        }

                        var name = Options.HtmlEncoder.Encode(parameter.Key);
                        var value = Options.HtmlEncoder.Encode(parameter.Value);

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

            // Return true to stop processing the request.
            return true;
        }

        private async Task<bool> SendErrorPageAsync(OpenIdConnectMessage response) {
            // Use a generic error if none has been explicitly provided.
            if (string.IsNullOrEmpty(response.Error)) {
                response.Error = OpenIdConnectConstants.Errors.InvalidRequest;
            }

            if (Options.ApplicationCanDisplayErrors) {
                Context.SetOpenIdConnectResponse(response);

                // Apply a 400 status code by default.
                Response.StatusCode = 400;

                // Return false to allow the rest of
                // the pipeline to handle the request.
                return false;
            }

            // Render the default error page.
            await SendNativeErrorPageAsync(response);

            // Return true to stop processing the request.
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