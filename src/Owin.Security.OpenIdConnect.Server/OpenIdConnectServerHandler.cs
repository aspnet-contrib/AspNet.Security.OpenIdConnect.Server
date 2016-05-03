/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Protocols;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Owin.Security.OpenIdConnect.Extensions;

namespace Owin.Security.OpenIdConnect.Server {
    internal partial class OpenIdConnectServerHandler : AuthenticationHandler<OpenIdConnectServerOptions> {
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

            else if (Options.UserinfoEndpointPath.HasValue &&
                     Options.UserinfoEndpointPath == Request.Path) {
                notification.MatchesUserinfoEndpoint();
            }

            await Options.Provider.MatchEndpoint(notification);

            if (!notification.IsAuthorizationEndpoint &&
                !notification.IsLogoutEndpoint &&
                !notification.IsUserinfoEndpoint) {
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
            // in this case, null is returned to indicate that authentication failed.
            if (request == null) {
                return null;
            }

            if (notification.IsAuthorizationEndpoint || notification.IsLogoutEndpoint) {
                if (string.IsNullOrEmpty(request.IdTokenHint)) {
                    return null;
                }

                var ticket = await DeserializeIdentityTokenAsync(request.IdTokenHint, request);
                if (ticket == null) {
                    Options.Logger.LogWarning("The identity token extracted from the id_token_hint " +
                                              "parameter was invalid and has been ignored.");

                    return null;
                }

                // Tickets are returned even if they
                // are considered invalid (e.g expired).
                return ticket;
            }

            else if (notification.IsUserinfoEndpoint) {
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

                var ticket = await DeserializeAccessTokenAsync(token, request);
                if (ticket == null) {
                    Options.Logger.LogWarning("The access token extracted from the userinfo " + 
                                              "request was invalid and has been ignored.");

                    return null;
                }

                if (!ticket.Properties.ExpiresUtc.HasValue ||
                     ticket.Properties.ExpiresUtc < Options.SystemClock.UtcNow) {
                    Options.Logger.LogWarning("The access token extracted from the userinfo " +
                                              "request was expired and has been ignored.");

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
            if (!Options.AllowInsecureHttp && string.Equals(Request.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase)) {
                // Return the native error page for endpoints involving the user participation.
                if (notification.IsAuthorizationEndpoint || notification.IsLogoutEndpoint) {
                    Options.Logger.LogWarning("The current request was rejected because the OpenID Connect server middleware " +
                                              "has been configured to reject HTTP requests. To permanently disable the transport " +
                                              "security requirement, set 'OpenIdConnectServerOptions.AllowInsecureHttp' to 'true'.");

                    return await SendNativePageAsync(new OpenIdConnectMessage {
                        Error = OpenIdConnectConstants.Errors.InvalidRequest,
                        ErrorDescription = "This server only accepts HTTPS requests."
                    });
                }

                // Return a JSON error for endpoints that don't involve the user participation.
                else if (notification.IsConfigurationEndpoint || notification.IsCryptographyEndpoint ||
                         notification.IsIntrospectionEndpoint || notification.IsRevocationEndpoint ||
                         notification.IsTokenEndpoint || notification.IsUserinfoEndpoint) {
                    Options.Logger.LogWarning("The current request was rejected because the OpenID Connect server middleware " +
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

        protected override async Task TeardownCoreAsync() {
            // Note: authentication handlers cannot reliabily write to the response stream
            // from ApplyResponseGrantAsync or ApplyResponseChallengeAsync because these methods
            // are susceptible to be invoked from AuthenticationHandler.OnSendingHeaderCallback,
            // where calling Write or WriteAsync on the response stream may result in a deadlock
            // on hosts using streamed responses. To work around this limitation, this class
            // doesn't implement ApplyResponseGrantAsync but TeardownCoreAsync, which is never called
            // by AuthenticationHandler.OnSendingHeaderCallback. In theory, this would prevent
            // OpenIdConnectServerHandler from both applying the response grant and allowing
            // the next middleware in the pipeline to alter the response stream but in practice,
            // OpenIdConnectServerHandler is assumed to be the only middleware allowed to write
            // to the response stream when a response grant has been applied.

            // Stop processing the request if no OpenID Connect
            // message has been found in the current context.
            var request = Context.GetOpenIdConnectRequest();
            if (request == null) {
                return;
            }

            await HandleAuthorizationResponseAsync();
            await HandleLogoutResponseAsync();
            await HandleForbiddenResponseAsync();
        }

        protected override async Task ApplyResponseChallengeAsync() {
            var context = Helper.LookupChallenge(Options.AuthenticationType, Options.AuthenticationMode);
            if (context == null || Response.StatusCode != 401) {
                return;
            }

            var notification = new MatchEndpointContext(Context, Options);

            if (Options.UserinfoEndpointPath.HasValue &&
                Options.UserinfoEndpointPath == Request.Path) {
                notification.MatchesUserinfoEndpoint();
            }

            await Options.Provider.MatchEndpoint(notification);

            if (!notification.IsUserinfoEndpoint) {
                return;
            }

            Response.StatusCode = 401;
            Response.Headers.Set("WWW-Authenticate", "error=" + OpenIdConnectConstants.Errors.InvalidGrant);
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

                Response.Headers.Set("Cache-Control", "no-cache");
                Response.Headers.Set("Pragma", "no-cache");
                Response.Headers.Set("Expires", "-1");

                buffer.Seek(offset: 0, loc: SeekOrigin.Begin);
                await buffer.CopyToAsync(Response.Body, 4096, Request.CallCancelled);

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

                Response.Headers.Set("Cache-Control", "no-cache");
                Response.Headers.Set("Pragma", "no-cache");
                Response.Headers.Set("Expires", "-1");

                buffer.Seek(offset: 0, loc: SeekOrigin.Begin);
                await buffer.CopyToAsync(Response.Body, 4096, Request.CallCancelled);

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
