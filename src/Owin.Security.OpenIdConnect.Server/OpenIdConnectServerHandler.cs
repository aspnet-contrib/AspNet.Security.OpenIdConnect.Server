/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/AspNet-OpenIdConnect-Server/Owin.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IdentityModel.Tokens;
using System.IO;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Protocols;
using Microsoft.Owin.Infrastructure;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using Newtonsoft.Json;
using Owin.Security.OpenIdConnect.Extensions;

namespace Owin.Security.OpenIdConnect.Server {
    internal class OpenIdConnectServerHandler : AuthenticationHandler<OpenIdConnectServerOptions> {
        private readonly ILogger _logger;
        private bool _headersSent = false;

        public OpenIdConnectServerHandler(ILogger logger) {
            _logger = logger;
        }

        protected override Task<AuthenticationTicket> AuthenticateCoreAsync() {
            return Task.FromResult<AuthenticationTicket>(null);
        }

        public override async Task<bool> InvokeAsync() {
            var matchRequestContext = new OpenIdConnectMatchEndpointContext(Context, Options);

            if (Options.AuthorizationEndpointPath == Request.Path) {
                matchRequestContext.MatchesAuthorizationEndpoint();
            }

            else if (Options.ConfigurationEndpointPath.HasValue && Options.ConfigurationEndpointPath == Request.Path) {
                matchRequestContext.MatchesConfigurationEndpoint();
            }

            else if (Options.KeysEndpointPath.HasValue && Options.KeysEndpointPath == Request.Path) {
                matchRequestContext.MatchesKeysEndpoint();
            }

            else if (Options.TokenEndpointPath.HasValue && Options.TokenEndpointPath == Request.Path) {
                matchRequestContext.MatchesTokenEndpoint();
            }

            await Options.Provider.MatchEndpoint(matchRequestContext);

            // Stop processing the request if MatchEndpoint called RequestCompleted.
            if (matchRequestContext.IsRequestCompleted) {
                return true;
            }

            if (matchRequestContext.IsAuthorizationEndpoint || matchRequestContext.IsConfigurationEndpoint ||
                matchRequestContext.IsKeysEndpoint || matchRequestContext.IsTokenEndpoint) {
                if (!Options.AllowInsecureHttp && string.Equals(Request.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase)) {
                    _logger.WriteWarning("Authorization server ignoring http request because AllowInsecureHttp is false.");
                    return false;
                }

                if (matchRequestContext.IsAuthorizationEndpoint) {
                    return await InvokeAuthorizationEndpointAsync();
                }

                if (matchRequestContext.IsConfigurationEndpoint) {
                    await InvokeConfigurationEndpointAsync();
                    return true;
                }

                if (matchRequestContext.IsKeysEndpoint) {
                    await InvokeKeysEndpointAsync();
                    return true;
                }

                if (matchRequestContext.IsTokenEndpoint) {
                    await InvokeTokenEndpointAsync();
                    return true;
                }
            }

            return false;
        }

        private async Task<bool> InvokeAuthorizationEndpointAsync() {
            OpenIdConnectMessage request = null;

            if (!string.Equals(Request.Method, "GET", StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(Request.Method, "POST", StringComparison.OrdinalIgnoreCase)) {
                return await SendErrorPageAsync(new OpenIdConnectMessage {
                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = "A malformed authorization request has been received: " +
                        "make sure to use either GET or POST."
                });
            }

            if (string.Equals(Request.Method, "GET", StringComparison.OrdinalIgnoreCase)) {
                request = new OpenIdConnectMessage(Request.Query) {
                    RequestType = OpenIdConnectRequestType.AuthenticationRequest
                };
            }

            else {
                // See http://openid.net/specs/openid-connect-core-1_0.html#FormSerialization
                if (string.IsNullOrWhiteSpace(Request.ContentType)) {
                    return await SendErrorPageAsync(new OpenIdConnectMessage {
                        Error = OpenIdConnectConstants.Errors.InvalidRequest,
                        ErrorDescription = "A malformed authorization request has been received: " +
                            "the mandatory 'Content-Type' header was missing from the POST request."
                    });
                }

                // May have media/type; charset=utf-8, allow partial match.
                if (!Request.ContentType.StartsWith("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase)) {
                    return await SendErrorPageAsync(new OpenIdConnectMessage {
                        Error = OpenIdConnectConstants.Errors.InvalidRequest,
                        ErrorDescription = "A malformed authorization request has been received: " +
                            "the 'Content-Type' header contained an unexcepted value. " +
                            "Make sure to use 'application/x-www-form-urlencoded'."
                    });
                }

                request = new OpenIdConnectMessage(await Request.ReadFormAsync()) {
                    RequestType = OpenIdConnectRequestType.AuthenticationRequest
                };
            }

            // Insert the authorization request in the OWIN context.
            Context.SetOpenIdConnectRequest(request);

            // While redirect_uri was not mandatory in OAuth2, this parameter
            // is now declared as REQUIRED and SHOULD cause an error when missing.
            // That said, the OIDC specs explicitly allow an authorization server to handle
            // a token request when redirect_uri was missing from the authorization request.
            // See http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
            // and http://openid.net/specs/openid-connect-core-1_0.html#TokenRequestValidation
            if (!string.IsNullOrEmpty(request.RedirectUri)) {
                Uri uri;
                if (!Uri.TryCreate(request.RedirectUri, UriKind.Absolute, out uri)) {
                    // redirect_uri MUST be an absolute URI.
                    // See http://tools.ietf.org/html/rfc6749#section-3.1.2
                    // and http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
                    return await SendErrorPageAsync(new OpenIdConnectMessage {
                        Error = OpenIdConnectConstants.Errors.InvalidRequest,
                        ErrorDescription = "redirect_uri must be absolute"
                    });
                }

                else if (!string.IsNullOrEmpty(uri.Fragment)) {
                    // redirect_uri MUST NOT include a fragment component.
                    // See http://tools.ietf.org/html/rfc6749#section-3.1.2
                    // and http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
                    return await SendErrorPageAsync(new OpenIdConnectMessage {
                        Error = OpenIdConnectConstants.Errors.InvalidRequest,
                        ErrorDescription = "redirect_uri must not include a fragment"
                    });
                }

                else if (!Options.AllowInsecureHttp && string.Equals(uri.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase)) {
                    // redirect_uri SHOULD require the use of TLS
                    // http://tools.ietf.org/html/rfc6749#section-3.1.2.1
                    // and http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
                    return await SendErrorPageAsync(new OpenIdConnectMessage {
                        Error = OpenIdConnectConstants.Errors.InvalidRequest,
                        ErrorDescription = "redirect_uri does not meet the security requirements"
                    });
                }
            }

            var clientContext = new OpenIdConnectValidateClientRedirectUriContext(Context, Options, request);
            await Options.Provider.ValidateClientRedirectUri(clientContext);

            if (!clientContext.IsValidated) {
                // Remove the unvalidated redirect_uri
                // from the authorization request.
                request.RedirectUri = null;

                // Update the authorization request in the OWIN context.
                Context.SetOpenIdConnectRequest(request);

                _logger.WriteVerbose("Unable to validate client information");

                return await SendErrorRedirectAsync(request, new OpenIdConnectMessage {
                    Error = clientContext.Error,
                    ErrorDescription = clientContext.ErrorDescription,
                    ErrorUri = clientContext.ErrorUri
                });
            }

            if (string.IsNullOrEmpty(request.ResponseType)) {
                _logger.WriteVerbose("Authorization request missing required response_type parameter");

                return await SendErrorRedirectAsync(request, new OpenIdConnectMessage {
                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = "response_type parameter missing",
                    RedirectUri = request.RedirectUri, State = request.State
                });
            }

            else if (!request.IsAuthorizationCodeFlow() && !request.IsImplicitFlow() && !request.IsHybridFlow()) {
                _logger.WriteVerbose("Authorization request contains unsupported response_type parameter");

                return await SendErrorRedirectAsync(request, new OpenIdConnectMessage {
                    Error = OpenIdConnectConstants.Errors.UnsupportedResponseType,
                    ErrorDescription = "response_type unsupported",
                    RedirectUri = request.RedirectUri, State = request.State
                });
            }

            else if (!request.IsFormPostResponseMode() && !request.IsFragmentResponseMode() && !request.IsQueryResponseMode()) {
                _logger.WriteVerbose("Authorization request contains unsupported response_mode parameter");

                return await SendErrorRedirectAsync(request, new OpenIdConnectMessage {
                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = "response_mode unsupported",
                    RedirectUri = request.RedirectUri, State = request.State
                });
            }

            else if (!request.HasComponent(message => message.Scope, OpenIdConnectScopes.OpenId) &&
                request.HasComponent(message => message.ResponseType, OpenIdConnectConstants.ResponseTypes.IdToken)) {
                _logger.WriteVerbose("The 'openid' scope part was missing");

                return await SendErrorRedirectAsync(request, new OpenIdConnectMessage {
                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = "openid scope missing",
                    RedirectUri = request.RedirectUri, State = request.State
                });
            }

            var validatingContext = new OpenIdConnectValidateAuthorizationRequestContext(Context, Options, request, clientContext);
            await Options.Provider.ValidateAuthorizationRequest(validatingContext);

            // Stop processing the request if Validated was not called.
            if (!validatingContext.IsValidated) {
                return await SendErrorRedirectAsync(request, new OpenIdConnectMessage {
                    Error = validatingContext.Error,
                    ErrorDescription = validatingContext.ErrorDescription,
                    ErrorUri = validatingContext.ErrorUri,
                    RedirectUri = request.RedirectUri, State = request.State
                });
            }

            var authorizationEndpointContext = new OpenIdConnectAuthorizationEndpointContext(Context, Options, request);
            await Options.Provider.AuthorizationEndpoint(authorizationEndpointContext);

            // Update the authorization request in the OWIN context.
            Context.SetOpenIdConnectRequest(request);

            // Stop processing the request if AuthorizationEndpoint called RequestCompleted.
            if (authorizationEndpointContext.IsRequestCompleted) {
                return true;
            }

            return false;
        }

        protected override async Task InitializeCoreAsync() {
            Response.OnSendingHeaders(state => {
                var handler = (OpenIdConnectServerHandler) state;
                handler._headersSent = true;
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
            // request may be null when no authorization request has been received
            // or has been already handled by InvokeAuthorizationEndpointAsync.
            OpenIdConnectMessage request = Context.GetOpenIdConnectRequest();
            if (request == null) {
                return;
            }

            // Stop processing the request if an authorization response has been forged by the inner application.
            // This allows the next middleware to return an OpenID Connect error or a custom response to the client.
            OpenIdConnectMessage response = Context.GetOpenIdConnectResponse();
            if (response != null && !string.IsNullOrWhiteSpace(response.RedirectUri)) {
                if (!string.IsNullOrWhiteSpace(response.Error)) {
                    await SendErrorRedirectAsync(request, response);
                    return;
                }

                await ApplyAuthorizationResponseAsync(request, response);
                return;
            }

            // Stop processing the request if there's no response grant that matches
            // the authentication type associated with this middleware instance
            // or if the response status code doesn't indicate a successful response.
            AuthenticationResponseGrant grant = Helper.LookupSignIn(Options.AuthenticationType);
            if (grant == null || Response.StatusCode != 200) {
                return;
            }

            if (_headersSent) {
                _logger.WriteCritical(
                    "OpenIdConnectServerHandler.TeardownCoreAsync cannot be called when " +
                    "the response headers have already been sent back to the user agent. " +
                    "Make sure the response body has not been altered and that no middleware " +
                    "has attempted to write to the response stream during this request.");
                return;
            }

            response = new OpenIdConnectMessage {
                ClientId = request.ClientId,
                Nonce = request.Nonce,
                RedirectUri = request.RedirectUri,
                State = request.State
            };

            DateTimeOffset currentUtc = Options.SystemClock.UtcNow;

            // Associate client_id with all subsequent tickets.
            grant.Properties.Dictionary[OpenIdConnectConstants.Extra.ClientId] = request.ClientId;
            if (!string.IsNullOrEmpty(request.RedirectUri)) {
                // Keep original request parameter for later comparison.
                grant.Properties.Dictionary[OpenIdConnectConstants.Extra.RedirectUri] = request.RedirectUri;
            }

            // Determine whether an authorization code should be returned.
            if (request.HasComponent(message => message.ResponseType, OpenIdConnectConstants.ResponseTypes.Code)) {
                grant.Properties.IssuedUtc = currentUtc;
                grant.Properties.ExpiresUtc = currentUtc.Add(Options.AuthorizationCodeLifetime);

                var context = new AuthenticationTokenCreateContext(
                    Context, Options.AuthorizationCodeFormat,
                    new AuthenticationTicket(grant.Identity, grant.Properties));

                await Options.AuthorizationCodeProvider.CreateAsync(context);

                if (string.IsNullOrEmpty(context.Token)) {
                    _logger.WriteError("response_type code requires an Options.AuthorizationCodeProvider implementing a single-use token.");

                    await SendErrorRedirectAsync(request, new OpenIdConnectMessage {
                        Error = OpenIdConnectConstants.Errors.UnsupportedResponseType,
                        ErrorDescription = "response_type code requires an Options.AuthorizationCodeProvider",
                        RedirectUri = request.RedirectUri, State = request.State
                    });

                    return;
                }

                response.Code = context.Token;
            }

            // Determine whether an access token should be returned.
            if (request.HasComponent(message => message.ResponseType, OpenIdConnectConstants.ResponseTypes.Token)) {
                grant.Properties.IssuedUtc = currentUtc;
                grant.Properties.ExpiresUtc = currentUtc.Add(Options.AccessTokenLifetime);

                var context = new AuthenticationTokenCreateContext(
                    Context, Options.AccessTokenFormat,
                    new AuthenticationTicket(grant.Identity, grant.Properties));

                await Options.AccessTokenProvider.CreateAsync(context);

                var accessToken = context.Token;
                if (string.IsNullOrEmpty(accessToken)) {
                    accessToken = context.SerializeTicket();
                }

                response.AccessToken = accessToken;
                response.TokenType = OpenIdConnectConstants.TokenTypes.Bearer;

                DateTimeOffset? accessTokenExpiresUtc = context.Ticket.Properties.ExpiresUtc;
                if (accessTokenExpiresUtc.HasValue) {
                    TimeSpan? expiresTimeSpan = accessTokenExpiresUtc - currentUtc;
                    var expiresIn = (long) (expiresTimeSpan.Value.TotalSeconds + .5);

                    response.ExpiresIn = expiresIn.ToString(CultureInfo.InvariantCulture);
                }
            }

            // Determine whether an identity token should be returned.
            if (request.HasComponent(message => message.ResponseType, OpenIdConnectConstants.ResponseTypes.IdToken)) {
                grant.Properties.IssuedUtc = currentUtc;
                grant.Properties.ExpiresUtc = currentUtc.Add(Options.IdentityTokenLifetime);

                response.IdToken = CreateIdToken(grant.Identity, response, grant.Properties);
            }

            var authorizationEndpointResponseContext = new OpenIdConnectAuthorizationEndpointResponseContext(
                Context, Options, new AuthenticationTicket(grant.Identity, grant.Properties), request, response);

            await Options.Provider.AuthorizationEndpointResponse(authorizationEndpointResponseContext);

            // Stop processing the request if AuthorizationEndpointResponse called RequestCompleted.
            if (authorizationEndpointResponseContext.IsRequestCompleted) {
                return;
            }

            await ApplyAuthorizationResponseAsync(request, response);
        }

        private async Task<bool> ApplyAuthorizationResponseAsync(OpenIdConnectMessage request, OpenIdConnectMessage response) {
            if (request.IsFormPostResponseMode()) {
                using (var buffer = new MemoryStream())
                using (var writer = new StreamWriter(buffer)) {
                    writer.WriteLine("<!doctype html>");
                    writer.WriteLine("<html>");
                    writer.WriteLine("<body>");
                    writer.WriteLine("<form name='form' method='post' action='" + response.RedirectUri + "'>");

                    foreach (KeyValuePair<string, string> parameter in response.Parameters) {
                        // Don't include client_id, redirect_uri or response_mode in the form.
                        if (string.Equals(parameter.Key, OpenIdConnectParameterNames.ClientId, StringComparison.Ordinal) ||
                            string.Equals(parameter.Key, OpenIdConnectParameterNames.RedirectUri, StringComparison.Ordinal) ||
                            string.Equals(parameter.Key, OpenIdConnectParameterNames.ResponseMode, StringComparison.Ordinal)) {
                            continue;
                        }

                        string key = WebUtility.HtmlEncode(parameter.Key);
                        string value = WebUtility.HtmlEncode(parameter.Value);

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
                string location = response.RedirectUri;
                var appender = new Appender(location, '#');

                foreach (KeyValuePair<string, string> parameter in response.Parameters) {
                    // Don't include client_id, redirect_uri or response_mode in the fragment.
                    if (string.Equals(parameter.Key, OpenIdConnectParameterNames.ClientId, StringComparison.Ordinal) || 
                        string.Equals(parameter.Key, OpenIdConnectParameterNames.RedirectUri, StringComparison.Ordinal) ||
                        string.Equals(parameter.Key, OpenIdConnectParameterNames.ResponseMode, StringComparison.Ordinal)) {
                        continue;
                    }

                    appender.Append(parameter.Key, parameter.Value);
                }

                Response.Redirect(appender.ToString());
                return true;
            }

            else if (request.IsQueryResponseMode()) {
                string location = response.RedirectUri;

                foreach (KeyValuePair<string, string> parameter in response.Parameters) {
                    // Don't include client_id, redirect_uri or response_mode in the query string.
                    if (string.Equals(parameter.Key, OpenIdConnectParameterNames.ClientId, StringComparison.Ordinal) || 
                        string.Equals(parameter.Key, OpenIdConnectParameterNames.RedirectUri, StringComparison.Ordinal) ||
                        string.Equals(parameter.Key, OpenIdConnectParameterNames.ResponseMode, StringComparison.Ordinal)) {
                        continue;
                    }

                    location = WebUtilities.AddQueryString(location, parameter.Key, parameter.Value);
                }

                Response.Redirect(location);
                return true;
            }

            return false;
        }

        private async Task InvokeConfigurationEndpointAsync() {
            var configurationEndpointContext = new OpenIdConnectConfigurationEndpointContext(Context, Options);
            await Options.Provider.ConfigurationEndpoint(configurationEndpointContext);

            // Stop processing the request if
            // ConfigurationEndpoint called RequestCompleted.
            if (configurationEndpointContext.IsRequestCompleted) {
                return;
            }

            // Metadata requests must be made via GET.
            // See http://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationRequest
            if (!string.Equals(Request.Method, "GET", StringComparison.OrdinalIgnoreCase)) {
                _logger.WriteError(string.Format(CultureInfo.InvariantCulture,
                    "Configuration endpoint: invalid method '{0}' used", Request.Method));
                return;
            }

            var configurationEndpointResponseContext = new OpenIdConnectConfigurationEndpointResponseContext(Context, Options);
            configurationEndpointResponseContext.Issuer = Options.Issuer;

            // Set the default endpoints concatenating Options.Issuer and Options.*EndpointPath.
            configurationEndpointResponseContext.AuthorizationEndpoint = Options.Issuer + Options.AuthorizationEndpointPath;

            // While the jwks_uri parameter is in principle mandatory, many OIDC clients are known
            // to work in a degraded mode when this parameter is not provided in the JSON response.
            // Making it mandatory in Owin.Security.OpenIdConnect.Server would prevent the end developer from
            // using custom security keys and manage himself the token validation parameters in the OIDC client.
            // To avoid this issue, the jwks_uri parameter is only added to the response when the JWKS endpoint
            // is believed to provide a valid response, which is the case with asymmetric keys supporting RSA-SHA256.
            // See http://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
            if (Options.SigningCredentials.SigningKey is AsymmetricSecurityKey &&
                Options.SigningCredentials.SigningKey.IsSupportedAlgorithm(SecurityAlgorithms.RsaSha256Signature)) {
                configurationEndpointResponseContext.KeyEndpoint = Options.Issuer + Options.KeysEndpointPath;
            }

            if (Options.TokenEndpointPath.HasValue) {
                configurationEndpointResponseContext.TokenEndpoint = Options.Issuer + Options.TokenEndpointPath;
            }

            configurationEndpointResponseContext.GrantTypes.Add(
                OpenIdConnectConstants.GrantTypes.AuthorizationCode);
            configurationEndpointResponseContext.GrantTypes.Add(
                OpenIdConnectConstants.GrantTypes.Implicit);

            configurationEndpointResponseContext.ResponseModes.Add(
                OpenIdConnectConstants.ResponseModes.FormPost);
            configurationEndpointResponseContext.ResponseModes.Add(
                OpenIdConnectConstants.ResponseModes.Fragment);
            configurationEndpointResponseContext.ResponseModes.Add(
                OpenIdConnectConstants.ResponseModes.Query);

            configurationEndpointResponseContext.ResponseTypes.Add(
                OpenIdConnectConstants.ResponseTypes.IdToken);
            configurationEndpointResponseContext.ResponseTypes.Add(
                OpenIdConnectConstants.ResponseTypes.Token);
            configurationEndpointResponseContext.ResponseTypes.Add(
                OpenIdConnectConstants.ResponseTypes.IdToken + ' ' +
                OpenIdConnectConstants.ResponseTypes.Token);

            // Don't expose response types containing code when
            // the token endpoint has been explicitly disabled.
            if (Options.TokenEndpointPath.HasValue) {
                configurationEndpointResponseContext.ResponseTypes.Add(
                    OpenIdConnectConstants.ResponseTypes.Code);

                configurationEndpointResponseContext.ResponseTypes.Add(
                    OpenIdConnectConstants.ResponseTypes.Code + ' ' +
                    OpenIdConnectConstants.ResponseTypes.IdToken);

                configurationEndpointResponseContext.ResponseTypes.Add(
                    OpenIdConnectConstants.ResponseTypes.Code + ' ' +
                    OpenIdConnectConstants.ResponseTypes.Token);

                configurationEndpointResponseContext.ResponseTypes.Add(
                    OpenIdConnectConstants.ResponseTypes.Code + ' ' +
                    OpenIdConnectConstants.ResponseTypes.IdToken + ' ' +
                    OpenIdConnectConstants.ResponseTypes.Token);
            }

            configurationEndpointResponseContext.Scopes.Add(OpenIdConnectScopes.OpenId);

            configurationEndpointResponseContext.SubjectTypes.Add(OpenIdConnectConstants.SubjectTypes.Public);
            configurationEndpointResponseContext.SubjectTypes.Add(OpenIdConnectConstants.SubjectTypes.Pairwise);

            configurationEndpointResponseContext.SigningAlgorithms.Add(OpenIdConnectConstants.Algorithms.RS256);

            await Options.Provider.ConfigurationEndpointResponse(configurationEndpointResponseContext);

            // Stop processing the request if ConfigurationEndpointResponse called RequestCompleted.
            if (configurationEndpointResponseContext.IsRequestCompleted) {
                return;
            }

            using (var buffer = new MemoryStream())
            using (var writer = new JsonTextWriter(new StreamWriter(buffer))) {
                writer.WriteStartObject();

                writer.WritePropertyName(OpenIdConnectConstants.Metadata.Issuer);
                writer.WriteValue(configurationEndpointResponseContext.Issuer);

                writer.WritePropertyName(OpenIdConnectConstants.Metadata.AuthorizationEndpoint);
                writer.WriteValue(configurationEndpointResponseContext.AuthorizationEndpoint);

                if (!string.IsNullOrWhiteSpace(configurationEndpointResponseContext.TokenEndpoint)) {
                    writer.WritePropertyName(OpenIdConnectConstants.Metadata.TokenEndpoint);
                    writer.WriteValue(configurationEndpointResponseContext.TokenEndpoint);
                }

                if (!string.IsNullOrWhiteSpace(configurationEndpointResponseContext.KeyEndpoint)) {
                    writer.WritePropertyName(OpenIdConnectConstants.Metadata.JwksUri);
                    writer.WriteValue(configurationEndpointResponseContext.KeyEndpoint);
                }

                writer.WritePropertyName(OpenIdConnectConstants.Metadata.GrantTypesSupported);
                writer.WriteStartArray();

                foreach (string type in configurationEndpointResponseContext.GrantTypes) {
                    writer.WriteValue(type);
                }

                writer.WriteEndArray();

                writer.WritePropertyName(OpenIdConnectConstants.Metadata.ResponseModesSupported);
                writer.WriteStartArray();

                foreach (string mode in configurationEndpointResponseContext.ResponseModes) {
                    writer.WriteValue(mode);
                }

                writer.WriteEndArray();

                writer.WritePropertyName(OpenIdConnectConstants.Metadata.ResponseTypesSupported);
                writer.WriteStartArray();

                foreach (string type in configurationEndpointResponseContext.ResponseTypes) {
                    writer.WriteValue(type);
                }

                writer.WriteEndArray();

                writer.WritePropertyName(OpenIdConnectConstants.Metadata.SubjectTypesSupported);
                writer.WriteStartArray();

                foreach (string type in configurationEndpointResponseContext.SubjectTypes) {
                    writer.WriteValue(type);
                }

                writer.WriteEndArray();

                writer.WritePropertyName(OpenIdConnectConstants.Metadata.ScopesSupported);
                writer.WriteStartArray();

                foreach (string algorithm in configurationEndpointResponseContext.Scopes) {
                    writer.WriteValue(algorithm);
                }

                writer.WriteEndArray();

                writer.WritePropertyName(OpenIdConnectConstants.Metadata.IdTokenSigningAlgValuesSupported);
                writer.WriteStartArray();

                foreach (string algorithm in configurationEndpointResponseContext.SigningAlgorithms) {
                    writer.WriteValue(algorithm);
                }

                writer.WriteEndArray();

                foreach (KeyValuePair<string, object> parameter in configurationEndpointResponseContext.AdditionalParameters) {
                    writer.WritePropertyName(parameter.Key);
                    writer.WriteValue(parameter.Value);
                }

                writer.WriteEndObject();
                writer.Flush();

                Response.ContentLength = buffer.Length;
                Response.ContentType = "application/json;charset=UTF-8";

                buffer.Seek(offset: 0, loc: SeekOrigin.Begin);
                await buffer.CopyToAsync(Response.Body, 4096, Request.CallCancelled);
            }
        }

        private async Task InvokeKeysEndpointAsync() {
            var keysEndpointContext = new OpenIdConnectKeysEndpointContext(Context, Options);
            await Options.Provider.KeysEndpoint(keysEndpointContext);
            
            // Skip processing the JWKS request if
            // RequestCompleted has been called.
            if (keysEndpointContext.IsRequestCompleted) {
                return;
            }

            // Metadata requests must be made via GET.
            // See http://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationRequest
            if (!string.Equals(Request.Method, "GET", StringComparison.OrdinalIgnoreCase)) {
                _logger.WriteError(string.Format(CultureInfo.InvariantCulture,
                    "Keys endpoint: invalid method '{0}' used", Request.Method));
                return;
            }

            var keysEndpointResponseContext = new OpenIdConnectKeysEndpointResponseContext(Context, Options);

            // Skip processing the metadata request if no supported key can be found.
            // Note: SigningKey is assumed to be never null under normal circonstances,
            // given that an initial check is made by SigningCredentials's constructor.
            // The SigningCredentials property is itself guarded against null values
            // in OpenIdConnectServerMiddleware's constructor.
            var asymmetricSecurityKey = Options.SigningCredentials.SigningKey as AsymmetricSecurityKey;
            if (asymmetricSecurityKey == null) {
                _logger.WriteError(string.Format(CultureInfo.InvariantCulture,
                    "Keys endpoint: invalid signing key registered. " +
                    "Make sure to provide an asymmetric security key deriving from '{0}'.",
                    typeof(AsymmetricSecurityKey).FullName));
                return;
            }

            if (!asymmetricSecurityKey.IsSupportedAlgorithm(SecurityAlgorithms.RsaSha256Signature)) {
                _logger.WriteError(string.Format(CultureInfo.InvariantCulture,
                    "Keys endpoint: invalid signing key registered. " +
                    "Make sure to provide a '{0}' instance exposing " +
                    "an asymmetric security key supporting the '{1}' algorithm.",
                    typeof(SigningCredentials).Name, SecurityAlgorithms.RsaSha256Signature));
                return;
            }

            X509Certificate2 x509Certificate = null;

            // Determine whether the signing credentials are directly based on a X.509 certificate.
            var x509SigningCredentials = Options.SigningCredentials as X509SigningCredentials;
            if (x509SigningCredentials != null) {
                x509Certificate = x509SigningCredentials.Certificate;
            }

            // Skip looking for a X509SecurityKey in SigningCredentials.SigningKey
            // if a certificate has been found in the SigningCredentials instance.
            if (x509Certificate == null) {
                // Determine whether the security key is an asymmetric key embedded in a X.509 certificate.
                var x509SecurityKey = Options.SigningCredentials.SigningKey as X509SecurityKey;
                if (x509SecurityKey != null) {
                    x509Certificate = x509SecurityKey.Certificate;
                }
            }

            // Skip looking for a X509AsymmetricSecurityKey in SigningCredentials.SigningKey
            // if a certificate has been found in SigningCredentials or SigningCredentials.SigningKey.
            if (x509Certificate == null) {
                // Determine whether the security key is an asymmetric key embedded in a X.509 certificate.
                var x509AsymmetricSecurityKey = Options.SigningCredentials.SigningKey as X509AsymmetricSecurityKey;
                if (x509AsymmetricSecurityKey != null) {
                    // The X.509 certificate is not directly accessible when using X509AsymmetricSecurityKey.
                    // Reflection is the only way to get the certificate used to create the security key.
                    var field = typeof(X509AsymmetricSecurityKey).GetField(
                        name: "certificate",
                        bindingAttr: BindingFlags.Instance | BindingFlags.NonPublic);

                    x509Certificate = (X509Certificate2) field.GetValue(x509AsymmetricSecurityKey);
                }
            }

            if (x509Certificate != null) {
                // Create a new JSON Web Key exposing the
                // certificate instead of its public RSA key.
                keysEndpointResponseContext.Keys.Add(new JsonWebKey {
                    Kty = JsonWebAlgorithmsKeyTypes.RSA,
                    Alg = JwtAlgorithms.RSA_SHA256,
                    Use = JsonWebKeyUseNames.Sig,

                    // x5t must be base64url-encoded.
                    // See http://tools.ietf.org/html/draft-ietf-jose-json-web-key-31#section-4.8
                    X5t = Base64UrlEncoder.Encode(x509Certificate.GetCertHash()),

                    // Unlike E or N, the certificates contained in x5c
                    // must be base64-encoded and not base64url-encoded.
                    // See http://tools.ietf.org/html/draft-ietf-jose-json-web-key-31#section-4.7
                    X5c = { Convert.ToBase64String(x509Certificate.RawData) }
                });
            }

            else {
                // Create a new JSON Web Key exposing the exponent and the modulus of the RSA public key.
                var asymmetricAlgorithm = (RSA) asymmetricSecurityKey.GetAsymmetricAlgorithm(
                    algorithm: SecurityAlgorithms.RsaSha256Signature, privateKey: false);

                // Export the RSA public key.
                var parameters = asymmetricAlgorithm.ExportParameters(
                    includePrivateParameters: false);

                keysEndpointResponseContext.Keys.Add(new JsonWebKey {
                    Kty = JsonWebAlgorithmsKeyTypes.RSA,
                    Alg = JwtAlgorithms.RSA_SHA256,
                    Use = JsonWebKeyUseNames.Sig,

                    // Both E and N must be base64url-encoded.
                    // See http://tools.ietf.org/html/draft-ietf-jose-json-web-key-31#appendix-A.1
                    E = Base64UrlEncoder.Encode(parameters.Exponent),
                    N = Base64UrlEncoder.Encode(parameters.Modulus)
                });
            }

            await Options.Provider.KeysEndpointResponse(keysEndpointResponseContext);

            // Skip processing the request if RequestCompleted has been called.
            if (keysEndpointResponseContext.IsRequestCompleted) {
                return;
            }

            // Ensure at least one key has been added to context.Keys.
            if (!keysEndpointResponseContext.Keys.Any()) {
                _logger.WriteError("Keys endpoint: no JSON Web Key found.");
                return;
            }

            using (var buffer = new MemoryStream())
            using (var writer = new JsonTextWriter(new StreamWriter(buffer))) {
                writer.WriteStartObject();

                writer.WritePropertyName(JsonWebKeyParameterNames.Keys);
                writer.WriteStartArray();
                writer.WriteStartObject();

                foreach (JsonWebKey key in keysEndpointResponseContext.Keys) {
                    // Ensure a key type has been provided.
                    // See http://tools.ietf.org/html/draft-ietf-jose-json-web-key-31#section-4.1
                    if (string.IsNullOrWhiteSpace(key.Kty)) {
                        _logger.WriteWarning("Keys endpoint: a JSON Web Key didn't " +
                            "contain the mandatory 'Kty' parameter and has been ignored.");
                        continue;
                    }

                    writer.WritePropertyName(JsonWebKeyParameterNames.Kty);
                    writer.WriteValue(key.Kty);

                    if (!string.IsNullOrWhiteSpace(key.Alg)) {
                        writer.WritePropertyName(JsonWebKeyParameterNames.Alg);
                        writer.WriteValue(key.Alg);
                    }

                    if (!string.IsNullOrWhiteSpace(key.E)) {
                        writer.WritePropertyName(JsonWebKeyParameterNames.E);
                        writer.WriteValue(key.E);
                    }

                    if (!string.IsNullOrWhiteSpace(key.KeyOps)) {
                        writer.WritePropertyName(JsonWebKeyParameterNames.KeyOps);
                        writer.WriteValue(key.KeyOps);
                    }

                    if (!string.IsNullOrWhiteSpace(key.Kid)) {
                        writer.WritePropertyName(JsonWebKeyParameterNames.Kid);
                        writer.WriteValue(key.Kid);
                    }

                    if (!string.IsNullOrWhiteSpace(key.N)) {
                        writer.WritePropertyName(JsonWebKeyParameterNames.N);
                        writer.WriteValue(key.N);
                    }

                    if (!string.IsNullOrWhiteSpace(key.Use)) {
                        writer.WritePropertyName(JsonWebKeyParameterNames.Use);
                        writer.WriteValue(key.Use);
                    }

                    if (!string.IsNullOrWhiteSpace(key.X5t)) {
                        writer.WritePropertyName(JsonWebKeyParameterNames.X5t);
                        writer.WriteValue(key.X5t);
                    }

                    if (!string.IsNullOrWhiteSpace(key.X5u)) {
                        writer.WritePropertyName(JsonWebKeyParameterNames.X5u);
                        writer.WriteValue(key.X5u);
                    }

                    if (key.X5c.Any()) {
                        writer.WritePropertyName(JsonWebKeyParameterNames.X5c);
                        writer.WriteStartArray();

                        foreach (string certificate in key.X5c) {
                            writer.WriteValue(certificate);
                        }

                        writer.WriteEndArray();
                    }
                }

                writer.WriteEndObject();
                writer.WriteEndArray();

                writer.WriteEndObject();
                writer.Flush();

                Response.ContentLength = buffer.Length;
                Response.ContentType = "application/json;charset=UTF-8";

                buffer.Seek(offset: 0, loc: SeekOrigin.Begin);
                await buffer.CopyToAsync(Response.Body, 4096, Request.CallCancelled);
            }
        }

        private async Task InvokeTokenEndpointAsync() {
            if (!string.Equals(Request.Method, "POST", StringComparison.OrdinalIgnoreCase)) {
                await SendErrorPayloadAsync(new OpenIdConnectMessage {
                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = "A malformed token request has been received: make sure to use POST."
                });

                return;
            }

            // See http://openid.net/specs/openid-connect-core-1_0.html#FormSerialization
            if (string.IsNullOrWhiteSpace(Request.ContentType)) {
                await SendErrorPayloadAsync(new OpenIdConnectMessage {
                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = "A malformed token request has been received: " +
                        "the mandatory 'Content-Type' header was missing from the POST request."
                });

                return;
            }

            // May have media/type; charset=utf-8, allow partial match.
            if (!Request.ContentType.StartsWith("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase)) {
                await SendErrorPayloadAsync(new OpenIdConnectMessage {
                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = "A malformed token request has been received: " +
                        "the 'Content-Type' header contained an unexcepted value. " +
                        "Make sure to use 'application/x-www-form-urlencoded'."
                });

                return;
            }

            var request = new OpenIdConnectMessage(await Request.ReadFormAsync());
            request.RequestType = OpenIdConnectRequestType.TokenRequest;

            DateTimeOffset currentUtc = Options.SystemClock.UtcNow;

            // Remove milliseconds in case they don't round-trip
            currentUtc = currentUtc.Subtract(TimeSpan.FromMilliseconds(currentUtc.Millisecond));

            var clientContext = new OpenIdConnectValidateClientAuthenticationContext(Context, Options, request);
            await Options.Provider.ValidateClientAuthentication(clientContext);

            if (!clientContext.IsValidated) {
                _logger.WriteError("clientID is not valid.");

                if (!clientContext.HasError) {
                    clientContext.SetError(OpenIdConnectConstants.Errors.InvalidClient);
                }

                await SendErrorPayloadAsync(new OpenIdConnectMessage {
                    Error = clientContext.Error,
                    ErrorDescription = clientContext.ErrorDescription,
                    ErrorUri = clientContext.ErrorUri
                });

                return;
            }

            var validatingContext = new OpenIdConnectValidateTokenRequestContext(Context, Options, request, clientContext);

            AuthenticationTicket ticket = null;
            if (request.IsAuthorizationCodeGrantType()) {
                // Authorization Code Grant http://tools.ietf.org/html/rfc6749#section-4.1
                // Access Token Request http://tools.ietf.org/html/rfc6749#section-4.1.3
                ticket = await InvokeTokenEndpointAuthorizationCodeGrantAsync(validatingContext, currentUtc);
            }

            else if (request.IsPasswordGrantType()) {
                // Resource Owner Password Credentials Grant http://tools.ietf.org/html/rfc6749#section-4.3
                // Access Token Request http://tools.ietf.org/html/rfc6749#section-4.3.2
                ticket = await InvokeTokenEndpointResourceOwnerPasswordCredentialsGrantAsync(validatingContext, currentUtc);
            }

            else if (request.IsClientCredentialsGrantType()) {
                // Client Credentials Grant http://tools.ietf.org/html/rfc6749#section-4.4
                // Access Token Request http://tools.ietf.org/html/rfc6749#section-4.4.2
                ticket = await InvokeTokenEndpointClientCredentialsGrantAsync(validatingContext, currentUtc);
            }

            else if (request.IsRefreshTokenGrantType()) {
                // Refreshing an Access Token
                // http://tools.ietf.org/html/rfc6749#section-6
                ticket = await InvokeTokenEndpointRefreshTokenGrantAsync(validatingContext, currentUtc);
            }

            else if (!string.IsNullOrWhiteSpace(request.GrantType)) {
                // Defining New Authorization Grant Types
                // http://tools.ietf.org/html/rfc6749#section-8.3
                ticket = await InvokeTokenEndpointCustomGrantAsync(validatingContext, currentUtc);
            }

            else {
                // Error Response http://tools.ietf.org/html/rfc6749#section-5.2
                // The authorization grant type is not supported by the
                // authorization server.
                _logger.WriteError("grant type is not recognized");
                validatingContext.SetError(OpenIdConnectConstants.Errors.UnsupportedGrantType);
            }

            if (ticket == null) {
                await SendErrorPayloadAsync(new OpenIdConnectMessage {
                    Error = validatingContext.Error,
                    ErrorDescription = validatingContext.ErrorDescription,
                    ErrorUri = validatingContext.ErrorUri
                });

                return;
            }

            ticket.Properties.IssuedUtc = currentUtc;
            ticket.Properties.ExpiresUtc = currentUtc.Add(Options.AccessTokenLifetime);

            var tokenEndpointContext = new OpenIdConnectTokenEndpointContext(Context, Options, ticket, request);
            await Options.Provider.TokenEndpoint(tokenEndpointContext);

            // Stop processing the request if
            // TokenEndpoint called RequestCompleted.
            if (tokenEndpointContext.IsRequestCompleted) {
                return;
            }

            if (tokenEndpointContext.TokenIssued) {
                ticket = new AuthenticationTicket(
                    tokenEndpointContext.Identity,
                    tokenEndpointContext.Properties);
            }

            else {
                _logger.WriteError("Token was not issued to tokenEndpointContext");

                await SendErrorPayloadAsync(new OpenIdConnectMessage {
                    Error = OpenIdConnectConstants.Errors.InvalidGrant,
                    ErrorDescription = "A token was not issued to tokenEndpointContext"
                });

                return;
            }

            var response = new OpenIdConnectMessage {
                TokenType = OpenIdConnectConstants.TokenTypes.Bearer
            };

            var accessTokenContext = new AuthenticationTokenCreateContext(
                Context, Options.AccessTokenFormat, ticket);

            await Options.AccessTokenProvider.CreateAsync(accessTokenContext);

            response.AccessToken = accessTokenContext.Token;
            if (string.IsNullOrEmpty(response.AccessToken)) {
                response.AccessToken = accessTokenContext.SerializeTicket();
            }

            DateTimeOffset? accessTokenExpiresUtc = ticket.Properties.ExpiresUtc;

            var refreshTokenCreateContext = new AuthenticationTokenCreateContext(
                Context, Options.RefreshTokenFormat, accessTokenContext.Ticket);

            await Options.RefreshTokenProvider.CreateAsync(refreshTokenCreateContext);

            response.SetParameter(OpenIdConnectConstants.Parameters.RefreshToken, refreshTokenCreateContext.Token);

            response.IdToken = CreateIdToken(ticket.Identity, request, ticket.Properties);

            if (accessTokenExpiresUtc.HasValue) {
                TimeSpan? expiresTimeSpan = accessTokenExpiresUtc - currentUtc;

                var expiresIn = (long) expiresTimeSpan.Value.TotalSeconds;
                if (expiresIn > 0) {
                    response.ExpiresIn = expiresIn.ToString(CultureInfo.InvariantCulture);
                }
            }

            var tokenEndpointResponseContext = new OpenIdConnectTokenEndpointResponseContext(
                Context, Options, ticket, request, response);

            await Options.Provider.TokenEndpointResponse(tokenEndpointResponseContext);

            // Stop processing the request if
            // TokenEndpointResponse called RequestCompleted.
            if (tokenEndpointResponseContext.IsRequestCompleted) {
                return;
            }

            using (var buffer = new MemoryStream())
            using (var writer = new JsonTextWriter(new StreamWriter(buffer))) {
                writer.WriteStartObject();

                foreach (KeyValuePair<string, string> parameter in response.Parameters) {
                    writer.WritePropertyName(parameter.Key);
                    writer.WriteValue(parameter.Value);
                }

                writer.WriteEndObject();
                writer.Flush();

                Response.ContentLength = buffer.Length;
                Response.ContentType = "application/json;charset=UTF-8";

                Response.Headers.Set("Cache-Control", "no-cache");
                Response.Headers.Set("Pragma", "no-cache");
                Response.Headers.Set("Expires", "-1");

                buffer.Seek(offset: 0, loc: SeekOrigin.Begin);
                await buffer.CopyToAsync(Response.Body, 4096, Request.CallCancelled);
            }
        }

        private async Task<AuthenticationTicket> InvokeTokenEndpointAuthorizationCodeGrantAsync(
            OpenIdConnectValidateTokenRequestContext validatingContext, DateTimeOffset currentUtc) {
            OpenIdConnectMessage tokenRequest = validatingContext.TokenRequest;

            var authorizationCodeContext = new AuthenticationTokenReceiveContext(
                Context, Options.AuthorizationCodeFormat, tokenRequest.Code);

            await Options.AuthorizationCodeProvider.ReceiveAsync(authorizationCodeContext);

            AuthenticationTicket ticket = authorizationCodeContext.Ticket;

            if (ticket == null) {
                _logger.WriteError("invalid authorization code");
                validatingContext.SetError(OpenIdConnectConstants.Errors.InvalidGrant);
                return null;
            }

            if (!ticket.Properties.ExpiresUtc.HasValue ||
                ticket.Properties.ExpiresUtc < currentUtc) {
                _logger.WriteError("expired authorization code");
                validatingContext.SetError(OpenIdConnectConstants.Errors.InvalidGrant);
                return null;
            }

            string clientId;
            if (!ticket.Properties.Dictionary.TryGetValue(OpenIdConnectConstants.Extra.ClientId, out clientId) ||
                !string.Equals(clientId, validatingContext.ClientContext.ClientId, StringComparison.Ordinal)) {
                _logger.WriteError("authorization code does not contain matching client_id");
                validatingContext.SetError(OpenIdConnectConstants.Errors.InvalidGrant);
                return null;
            }

            string redirectUri;
            if (ticket.Properties.Dictionary.TryGetValue(OpenIdConnectConstants.Extra.RedirectUri, out redirectUri)) {
                ticket.Properties.Dictionary.Remove(OpenIdConnectConstants.Extra.RedirectUri);
                if (!string.Equals(redirectUri, tokenRequest.RedirectUri, StringComparison.Ordinal)) {
                    _logger.WriteError("authorization code does not contain matching redirect_uri");
                    validatingContext.SetError(OpenIdConnectConstants.Errors.InvalidGrant);
                    return null;
                }
            }

            await Options.Provider.ValidateTokenRequest(validatingContext);

            var grantContext = new OpenIdConnectGrantAuthorizationCodeContext(Context, Options, tokenRequest, ticket);

            if (validatingContext.IsValidated) {
                await Options.Provider.GrantAuthorizationCode(grantContext);
            }

            return ReturnOutcome(
                validatingContext,
                grantContext,
                grantContext.Ticket,
                OpenIdConnectConstants.Errors.InvalidGrant);
        }

        private async Task<AuthenticationTicket> InvokeTokenEndpointResourceOwnerPasswordCredentialsGrantAsync(
            OpenIdConnectValidateTokenRequestContext validatingContext,
            DateTimeOffset currentUtc) {
            OpenIdConnectMessage tokenRequest = validatingContext.TokenRequest;

            await Options.Provider.ValidateTokenRequest(validatingContext);

            var grantContext = new OpenIdConnectGrantResourceOwnerCredentialsContext(Context, Options, tokenRequest);

            if (validatingContext.IsValidated) {
                await Options.Provider.GrantResourceOwnerCredentials(grantContext);
            }

            return ReturnOutcome(
                validatingContext,
                grantContext,
                grantContext.Ticket,
                OpenIdConnectConstants.Errors.InvalidGrant);
        }

        private async Task<AuthenticationTicket> InvokeTokenEndpointClientCredentialsGrantAsync(
            OpenIdConnectValidateTokenRequestContext validatingContext,
            DateTimeOffset currentUtc) {
            OpenIdConnectMessage tokenRequest = validatingContext.TokenRequest;

            await Options.Provider.ValidateTokenRequest(validatingContext);
            if (!validatingContext.IsValidated) {
                return null;
            }

            var grantContext = new OpenIdConnectGrantClientCredentialsContext(Context, Options, tokenRequest);

            await Options.Provider.GrantClientCredentials(grantContext);

            return ReturnOutcome(
                validatingContext,
                grantContext,
                grantContext.Ticket,
                OpenIdConnectConstants.Errors.UnauthorizedClient);
        }

        private async Task<AuthenticationTicket> InvokeTokenEndpointRefreshTokenGrantAsync(
            OpenIdConnectValidateTokenRequestContext validatingContext, DateTimeOffset currentUtc) {
            OpenIdConnectMessage tokenRequest = validatingContext.TokenRequest;

            var refreshTokenContext = new AuthenticationTokenReceiveContext(
                Context, Options.RefreshTokenFormat, tokenRequest.GetParameter("refresh_token"));

            await Options.RefreshTokenProvider.ReceiveAsync(refreshTokenContext);

            AuthenticationTicket ticket = refreshTokenContext.Ticket;

            if (ticket == null) {
                _logger.WriteError("invalid refresh token");
                validatingContext.SetError(OpenIdConnectConstants.Errors.InvalidGrant);
                return null;
            }

            if (!ticket.Properties.ExpiresUtc.HasValue ||
                ticket.Properties.ExpiresUtc < currentUtc) {
                _logger.WriteError("expired refresh token");
                validatingContext.SetError(OpenIdConnectConstants.Errors.InvalidGrant);
                return null;
            }

            await Options.Provider.ValidateTokenRequest(validatingContext);

            var grantContext = new OpenIdConnectGrantRefreshTokenContext(Context, Options, tokenRequest, ticket);

            if (validatingContext.IsValidated) {
                await Options.Provider.GrantRefreshToken(grantContext);
            }

            return ReturnOutcome(
                validatingContext,
                grantContext,
                grantContext.Ticket,
                OpenIdConnectConstants.Errors.InvalidGrant);
        }

        private async Task<AuthenticationTicket> InvokeTokenEndpointCustomGrantAsync(
            OpenIdConnectValidateTokenRequestContext validatingContext,
            DateTimeOffset currentUtc) {
            OpenIdConnectMessage tokenRequest = validatingContext.TokenRequest;

            await Options.Provider.ValidateTokenRequest(validatingContext);

            var grantContext = new OpenIdConnectGrantCustomExtensionContext(Context, Options, tokenRequest);

            if (validatingContext.IsValidated) {
                await Options.Provider.GrantCustomExtension(grantContext);
            }

            return ReturnOutcome(
                validatingContext,
                grantContext,
                grantContext.Ticket,
                OpenIdConnectConstants.Errors.UnsupportedGrantType);
        }

        private static string GenerateHash(string value, string algorithm = null) {
            using (var hashAlgorithm = HashAlgorithm.Create(algorithm)) {
                byte[] hashBytes = hashAlgorithm.ComputeHash(Encoding.UTF8.GetBytes(value));

                var hashString = Convert.ToBase64String(hashBytes, 0, hashBytes.Length / 2);
                hashString = hashString.Split('=')[0]; // Remove any trailing padding
                hashString = hashString.Replace('+', '-'); // 62nd char of encoding
                return hashString.Replace('/', '_'); // 63rd char of encoding
            }
        }

        private string CreateIdToken(ClaimsIdentity identity, OpenIdConnectMessage message, AuthenticationProperties properties) {
            var claims = Options.ServerClaimsMapper(identity.Claims).ToList();

            if (!string.IsNullOrEmpty(message.Code)) {
                var cHash = GenerateHash(message.Code, Options.SigningCredentials.DigestAlgorithm);
                claims.Add(new Claim(JwtRegisteredClaimNames.CHash, cHash));
            }

            if (!string.IsNullOrEmpty(message.AccessToken)) {
                var atHash = GenerateHash(message.AccessToken, Options.SigningCredentials.DigestAlgorithm);
                claims.Add(new Claim("at_hash", atHash));
            }

            if (!string.IsNullOrEmpty(message.Nonce)) {
                claims.Add(new Claim(JwtRegisteredClaimNames.Nonce, message.Nonce));
            }

            var iat = EpochTime.GetIntDate(Options.SystemClock.UtcNow.UtcDateTime).ToString();
            claims.Add(new Claim("iat", iat));

            DateTimeOffset notBefore = Options.SystemClock.UtcNow;
            DateTimeOffset expires = notBefore.Add(Options.IdentityTokenLifetime);

            string notBeforeString;
            if (properties.Dictionary.TryGetValue("IdTokenIssuedUtc", out notBeforeString)) {
                DateTimeOffset value;
                if (DateTimeOffset.TryParseExact(notBeforeString, "r", CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out value))
                    notBefore = value;
            }

            string expiresString;
            if (properties.Dictionary.TryGetValue("IdTokenExpiresUtc", out expiresString)) {
                DateTimeOffset value;
                if (DateTimeOffset.TryParseExact(expiresString, "r", CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out value))
                    expires = value;
            }

            var jwt = Options.TokenHandler.CreateToken(
                issuer: Options.Issuer,
                signingCredentials: Options.SigningCredentials,
                audience: message.ClientId,
                notBefore: notBefore.UtcDateTime,
                expires: expires.UtcDateTime,
                signatureProvider: Options.SignatureProvider
            );

            jwt.Payload.AddClaims(claims);

            var idToken = Options.TokenHandler.WriteToken(jwt);

            return idToken;
        }

        private static AuthenticationTicket ReturnOutcome(
            OpenIdConnectValidateTokenRequestContext validatingContext,
            BaseValidatingContext<OpenIdConnectServerOptions> grantContext,
            AuthenticationTicket ticket,
            string defaultError) {
            if (!validatingContext.IsValidated) {
                return null;
            }

            if (!grantContext.IsValidated) {
                if (grantContext.HasError) {
                    validatingContext.SetError(
                        grantContext.Error,
                        grantContext.ErrorDescription,
                        grantContext.ErrorUri);
                }
                else {
                    validatingContext.SetError(defaultError);
                }
                return null;
            }

            if (ticket == null) {
                validatingContext.SetError(defaultError);
                return null;
            }

            return ticket;
        }

        private async Task<bool> SendErrorRedirectAsync(OpenIdConnectMessage request, OpenIdConnectMessage response) {
            // Remove the authorization request from the OWIN context to inform
            // TeardownCoreAsync that there's nothing more to handle.
            Context.SetOpenIdConnectRequest(request: null);

            // Directly display an error page if redirect_uri cannot be used.
            if (string.IsNullOrWhiteSpace(response.RedirectUri)) {
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
            if (Options.ApplicationCanDisplayErrors) {
                Context.SetOpenIdConnectResponse(response);

                // Request is not handled - pass through to application for rendering.
                return false;
            }

            using (var buffer = new MemoryStream())
            using (var writer = new StreamWriter(buffer)) {
                writer.WriteLine("error: {0}", response.Error);

                if (!string.IsNullOrEmpty(response.ErrorDescription)) {
                    writer.WriteLine("error_description: {0}", response.ErrorDescription);
                }

                if (!string.IsNullOrEmpty(response.ErrorUri)) {
                    writer.WriteLine("error_uri: {0}", response.ErrorUri);
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

                return true;
            }
        }

        private async Task SendErrorPayloadAsync(OpenIdConnectMessage response) {
            using (var buffer = new MemoryStream())
            using (var writer = new JsonTextWriter(new StreamWriter(buffer))) {
                writer.WriteStartObject();
                writer.WritePropertyName(OpenIdConnectConstants.Parameters.Error);
                writer.WriteValue(response.Error);

                if (!string.IsNullOrEmpty(response.ErrorDescription)) {
                    writer.WritePropertyName(OpenIdConnectConstants.Parameters.ErrorDescription);
                    writer.WriteValue(response.ErrorDescription);
                }

                if (!string.IsNullOrEmpty(response.ErrorUri)) {
                    writer.WritePropertyName(OpenIdConnectConstants.Parameters.ErrorUri);
                    writer.WriteValue(response.ErrorUri);
                }

                writer.WriteEndObject();
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
