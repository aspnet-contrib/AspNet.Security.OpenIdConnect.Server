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
using Microsoft.AspNetCore.Http.Features.Authentication;
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

            else if (Options.TokenEndpointPath.HasValue &&
                     Options.TokenEndpointPath == Request.Path) {
                notification.MatchesTokenEndpoint();
            }

            else if (Options.IntrospectionEndpointPath.HasValue &&
                     Options.IntrospectionEndpointPath == Request.Path) {
                notification.MatchesIntrospectionEndpoint();
            }

            else if (Options.UserinfoEndpointPath.HasValue &&
                     Options.UserinfoEndpointPath == Request.Path) {
                notification.MatchesUserinfoEndpoint();
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
                    Logger.LogWarning("The current request was rejected because the OpenID Connect server middleware " +
                                      "has been configured to reject HTTP requests. To permanently disable the transport " +
                                      "security requirement, set 'OpenIdConnectServerOptions.AllowInsecureHttp' to 'true'.");

                    return await SendNativePageAsync(new OpenIdConnectMessage {
                        Error = OpenIdConnectConstants.Errors.InvalidRequest,
                        ErrorDescription = "This server only accepts HTTPS requests."
                    });
                }

                // Return a JSON error for endpoints that don't involve the user participation.
                else if (notification.IsTokenEndpoint || notification.IsUserinfoEndpoint ||
                         notification.IsIntrospectionEndpoint || notification.IsConfigurationEndpoint ||
                         notification.IsCryptographyEndpoint) {
                    Logger.LogWarning("The current request was rejected because the OpenID Connect server middleware " +
                                      "has been configured to reject HTTP requests. To permanently disable the transport " +
                                      "security requirement, set 'OpenIdConnectServerOptions.AllowInsecureHttp' to 'true'.");

                    return await SendPayloadAsync(new OpenIdConnectMessage {
                        Error = OpenIdConnectConstants.Errors.InvalidRequest,
                        ErrorDescription = "This server only accepts HTTPS requests."
                    });
                }
            }

            if (notification.IsAuthorizationEndpoint) {
                return await InvokeAuthorizationEndpointAsync();
            }

            else if (notification.IsLogoutEndpoint) {
                return await InvokeLogoutEndpointAsync();
            }

            else if (notification.IsTokenEndpoint) {
                return await InvokeTokenEndpointAsync();
            }

            else if (notification.IsIntrospectionEndpoint) {
                return await InvokeIntrospectionEndpointAsync();
            }

            else if (notification.IsUserinfoEndpoint) {
                return await InvokeUserinfoEndpointAsync();
            }

            else if (notification.IsConfigurationEndpoint) {
                return await InvokeConfigurationEndpointAsync();
            }

            else if (notification.IsCryptographyEndpoint) {
                return await InvokeCryptographyEndpointAsync();
            }

            return false;
        }

        protected override async Task<bool> HandleUnauthorizedAsync(ChallengeContext context) {
            var notification = new MatchEndpointContext(Context, Options);

            if (Options.UserinfoEndpointPath.HasValue &&
                Options.UserinfoEndpointPath == Request.Path) {
                notification.MatchesUserinfoEndpoint();
            }

            await Options.Provider.MatchEndpoint(notification);

            // Return true to indicate to the authentication pipeline that
            // the 401 response shouldn't be handled by the other middleware.
            if (!notification.IsUserinfoEndpoint) {
                return true;
            }

            Response.StatusCode = 401;
            Response.Headers[HeaderNames.WWWAuthenticate] = "error=" + OpenIdConnectConstants.Errors.InvalidGrant;

            return false;
        }

        private async Task<bool> SendNativePageAsync(OpenIdConnectMessage response) {
            using (var buffer = new MemoryStream())
            using (var writer = new StreamWriter(buffer)) {
                foreach (var parameter in response.Parameters) {
                    writer.WriteLine("{0}: {1}", parameter.Key, parameter.Value);
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

        private Task<bool> SendPayloadAsync(OpenIdConnectMessage response) {
            var payload = new JObject();

            foreach (var parameter in response.Parameters) {
                payload[parameter.Key] = parameter.Value;
            }

            return SendPayloadAsync(payload);
        }

        private async Task<bool> SendPayloadAsync(JObject response) {
            using (var buffer = new MemoryStream())
            using (var writer = new JsonTextWriter(new StreamWriter(buffer))) {
                response.WriteTo(writer);
                writer.Flush();

                var error = response[OpenIdConnectConstants.Parameters.Error];
                if (error != null) {
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