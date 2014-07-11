// Copyright (c) Microsoft Open Technologies, Inc. All rights reserved. See License.txt in the project root for license information.

namespace Microsoft.Owin.Security.OpenIdConnect.Server {
    using System;
    using System.Collections.Generic;
    using System.Diagnostics.CodeAnalysis;
    using System.Globalization;
    using System.IdentityModel.Tokens;
    using System.IO;
    using System.Linq;
    using System.Security.Claims;
    using System.Text;
    using System.Threading.Tasks;
    using Microsoft.IdentityModel.Protocols;
    using Microsoft.Owin.Infrastructure;
    using Microsoft.Owin.Logging;
    using Microsoft.Owin.Security.Infrastructure;
    using Microsoft.Owin.Security.OpenIdConnect.Server.Messages;
    using Newtonsoft.Json;

    internal class OpenIdConnectServerHandler : AuthenticationHandler<OpenIdConnectServerOptions> {
        private readonly ILogger _logger;

        private AuthorizeEndpointRequest _authorizeEndpointRequest;
        private OpenIdConnectValidateClientRedirectUriContext _clientContext;

        public OpenIdConnectServerHandler(ILogger logger) {
            _logger = logger;
        }

        protected override Task<AuthenticationTicket> AuthenticateCoreAsync() {
            return Task.FromResult<AuthenticationTicket>(null);
        }

        public override async Task<bool> InvokeAsync() {
            var matchRequestContext = new OpenIdConnectMatchEndpointContext(Context, Options);
            if (Options.AuthorizeEndpointPath.HasValue && Options.AuthorizeEndpointPath == Request.Path) {
                matchRequestContext.MatchesAuthorizeEndpoint();
            }
            else if (Options.TokenEndpointPath.HasValue && Options.TokenEndpointPath == Request.Path) {
                matchRequestContext.MatchesTokenEndpoint();
            }
            await Options.Provider.MatchEndpoint(matchRequestContext);
            if (matchRequestContext.IsRequestCompleted) {
                return true;
            }

            if (matchRequestContext.IsAuthorizeEndpoint || matchRequestContext.IsTokenEndpoint) {
                if (!Options.AllowInsecureHttp &&
                    String.Equals(Request.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase)) {
                    _logger.WriteWarning("Authorization server ignoring http request because AllowInsecureHttp is false.");
                    return false;
                }
                if (matchRequestContext.IsAuthorizeEndpoint) {
                    return await InvokeAuthorizeEndpointAsync();
                }
                if (matchRequestContext.IsTokenEndpoint) {
                    await InvokeTokenEndpointAsync();
                    return true;
                }
            }
            return false;
        }

        private async Task<bool> InvokeAuthorizeEndpointAsync() {
            var authorizeRequest = new AuthorizeEndpointRequest(Request.Query);

            var clientContext = new OpenIdConnectValidateClientRedirectUriContext(
                Context,
                Options,
                authorizeRequest.ClientId,
                authorizeRequest.RedirectUri);

            if (!String.IsNullOrEmpty(authorizeRequest.RedirectUri)) {
                bool acceptableUri = true;
                Uri validatingUri;
                if (!Uri.TryCreate(authorizeRequest.RedirectUri, UriKind.Absolute, out validatingUri)) {
                    // The redirection endpoint URI MUST be an absolute URI
                    // http://tools.ietf.org/html/rfc6749#section-3.1.2
                    acceptableUri = false;
                }
                else if (!String.IsNullOrEmpty(validatingUri.Fragment)) {
                    // The endpoint URI MUST NOT include a fragment component.
                    // http://tools.ietf.org/html/rfc6749#section-3.1.2
                    acceptableUri = false;
                }
                else if (!Options.AllowInsecureHttp &&
                    String.Equals(validatingUri.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase)) {
                    // The redirection endpoint SHOULD require the use of TLS
                    // http://tools.ietf.org/html/rfc6749#section-3.1.2.1
                    acceptableUri = false;
                }
                if (!acceptableUri) {
                    clientContext.SetError(Constants.Errors.InvalidRequest);
                    return await SendErrorRedirectAsync(clientContext, clientContext);
                }
            }

            await Options.Provider.ValidateClientRedirectUri(clientContext);

            if (!clientContext.IsValidated) {
                _logger.WriteVerbose("Unable to validate client information");
                return await SendErrorRedirectAsync(clientContext, clientContext);
            }

            var validatingContext = new OpenIdConnectValidateAuthorizeRequestContext(
                Context,
                Options,
                authorizeRequest,
                clientContext);

            if (string.IsNullOrEmpty(authorizeRequest.ResponseType)) {
                _logger.WriteVerbose("Authorize endpoint request missing required response_type parameter");
                validatingContext.SetError(Constants.Errors.InvalidRequest);
            }
            else if (!authorizeRequest.IsAuthorizationCodeGrantType &&
                !authorizeRequest.IsImplicitGrantType &&
                !authorizeRequest.IsHybridGrantType) {
                _logger.WriteVerbose("Authorize endpoint request contains unsupported response_type parameter");
                validatingContext.SetError(Constants.Errors.UnsupportedResponseType);
            }
            else if (!authorizeRequest.Scope.Contains(OpenIdConnectScopes.OpenId)) {
                _logger.WriteVerbose("The 'openid' scope part was missing");
                validatingContext.SetError(Constants.Errors.InvalidRequest);
            }
            else {
                await Options.Provider.ValidateAuthorizeRequest(validatingContext);
            }

            if (!validatingContext.IsValidated) {
                // an invalid request is not processed further
                return await SendErrorRedirectAsync(clientContext, validatingContext);
            }

            _clientContext = clientContext;
            _authorizeEndpointRequest = authorizeRequest;

            var authorizeEndpointContext = new OpenIdConnectAuthorizeEndpointContext(Context, Options, authorizeRequest);

            await Options.Provider.AuthorizeEndpoint(authorizeEndpointContext);

            return authorizeEndpointContext.IsRequestCompleted;
        }

        protected override async Task ApplyResponseGrantAsync() {
            // only successful results of an authorize request are altered
            if (_clientContext == null ||
                _authorizeEndpointRequest == null ||
                Response.StatusCode != 200) {
                return;
            }

            // only apply with signin of matching authentication type
            AuthenticationResponseGrant signin = Helper.LookupSignIn(Options.AuthenticationType);
            if (signin == null) {
                return;
            }

            var returnParameters = new Dictionary<string, string>();

            if (_authorizeEndpointRequest.IsAuthorizationCodeGrantType || _authorizeEndpointRequest.IsHybridGrantType) {
                DateTimeOffset currentUtc = Options.SystemClock.UtcNow;
                signin.Properties.IssuedUtc = currentUtc;
                signin.Properties.ExpiresUtc = currentUtc.Add(Options.AuthorizationCodeExpireTimeSpan);

                // associate client_id with all subsequent tickets
                signin.Properties.Dictionary[Constants.Extra.ClientId] = _authorizeEndpointRequest.ClientId;
                if (!string.IsNullOrEmpty(_authorizeEndpointRequest.RedirectUri)) {
                    // keep original request parameter for later comparison
                    signin.Properties.Dictionary[Constants.Extra.RedirectUri] = _authorizeEndpointRequest.RedirectUri;
                }

                string code = null, accessToken = null;

                if (_authorizeEndpointRequest.ContainsGrantType(Constants.ResponseTypes.Code)) {
                    var context = new AuthenticationTokenCreateContext(
                        Context,
                        Options.AuthorizationCodeFormat,
                        new AuthenticationTicket(signin.Identity, signin.Properties));

                    await Options.AuthorizationCodeProvider.CreateAsync(context);

                    code = context.Token;
                    if (string.IsNullOrEmpty(code)) {
                        _logger.WriteError("response_type code requires an Options.AuthorizationCodeProvider implementing a single-use token.");
                        var errorContext = new OpenIdConnectValidateAuthorizeRequestContext(Context, Options, _authorizeEndpointRequest, _clientContext);
                        errorContext.SetError(Constants.Errors.UnsupportedResponseType);
                        await SendErrorRedirectAsync(_clientContext, errorContext);
                        return;
                    }

                    returnParameters[Constants.Parameters.Code] = code;
                }

                if (_authorizeEndpointRequest.ContainsGrantType(Constants.ResponseTypes.Token)) {
                    var accessTokenContext = new AuthenticationTokenCreateContext(
                        Context,
                        Options.AccessTokenFormat,
                        new AuthenticationTicket(signin.Identity, signin.Properties));

                    await Options.AccessTokenProvider.CreateAsync(accessTokenContext);

                    accessToken = accessTokenContext.Token;
                    if (string.IsNullOrEmpty(accessToken)) {
                        accessToken = accessTokenContext.SerializeTicket();
                    }

                    returnParameters[Constants.Parameters.AccessToken] = accessToken;
                    returnParameters[Constants.Parameters.TokenType] = Constants.TokenTypes.Bearer;

                    DateTimeOffset? accessTokenExpiresUtc = accessTokenContext.Ticket.Properties.ExpiresUtc;

                    if (accessTokenExpiresUtc.HasValue) {
                        TimeSpan? expiresTimeSpan = accessTokenExpiresUtc - currentUtc;
                        var expiresIn = (long) (expiresTimeSpan.Value.TotalSeconds + .5);
                        returnParameters[Constants.Parameters.ExpiresIn] = expiresIn.ToString(CultureInfo.InvariantCulture);
                    }
                }

                var authResponseContext = new OpenIdConnectAuthorizationEndpointResponseContext(
                    Context, Options, new AuthenticationTicket(signin.Identity, signin.Properties),
                    _authorizeEndpointRequest, accessToken, code);

                if (_authorizeEndpointRequest.ContainsGrantType(OpenIdConnectResponseTypes.IdToken)) {
                    var idToken = CreateIdToken(
                        authResponseContext.Identity, authResponseContext.Properties,
                        authResponseContext.AuthorizeEndpointRequest.ClientId, authResponseContext.AccessToken,
                        authResponseContext.AuthorizationCode, authResponseContext.Request.Query["nonce"]);

                    returnParameters[Constants.Parameters.IdToken] = idToken;
                }

                await Options.Provider.AuthorizationEndpointResponse(authResponseContext);

                foreach (var parameter in authResponseContext.AdditionalResponseParameters) {
                    returnParameters[parameter.Key] = parameter.Value.ToString();
                }

                if (!String.IsNullOrEmpty(_authorizeEndpointRequest.State)) {
                    returnParameters[Constants.Parameters.State] = _authorizeEndpointRequest.State;
                }

                string location = string.Empty;
                if (_authorizeEndpointRequest.IsFormPostResponseMode) {
                    location = Options.FormPostEndpoint.ToString();
                    returnParameters[Constants.Parameters.RedirectUri] = _clientContext.RedirectUri;
                }
                else {
                    location = _clientContext.RedirectUri;
                }

                foreach (var key in returnParameters.Keys) {
                    location = WebUtilities.AddQueryString(location, key, returnParameters[key]);
                }

                Response.Redirect(location);
            }

            else if (_authorizeEndpointRequest.IsImplicitGrantType) {
                string location = _clientContext.RedirectUri;

                DateTimeOffset currentUtc = Options.SystemClock.UtcNow;
                signin.Properties.IssuedUtc = currentUtc;
                signin.Properties.ExpiresUtc = currentUtc.Add(Options.AccessTokenExpireTimeSpan);

                // associate client_id with access token
                signin.Properties.Dictionary[Constants.Extra.ClientId] = _authorizeEndpointRequest.ClientId;

                string accessToken = null;
                var appender = new Appender(location, '#');

                if (_authorizeEndpointRequest.ContainsGrantType(Constants.ResponseTypes.Token)) {
                    var accessTokenContext = new AuthenticationTokenCreateContext(
                        Context,
                        Options.AccessTokenFormat,
                        new AuthenticationTicket(signin.Identity, signin.Properties));

                    await Options.AccessTokenProvider.CreateAsync(accessTokenContext);

                    accessToken = accessTokenContext.Token;
                    if (string.IsNullOrEmpty(accessToken)) {
                        accessToken = accessTokenContext.SerializeTicket();
                    }

                    DateTimeOffset? accessTokenExpiresUtc = accessTokenContext.Ticket.Properties.ExpiresUtc;

                    appender
                        .Append(Constants.Parameters.AccessToken, accessToken)
                        .Append(Constants.Parameters.TokenType, Constants.TokenTypes.Bearer);

                    if (accessTokenExpiresUtc.HasValue) {
                        TimeSpan? expiresTimeSpan = accessTokenExpiresUtc - currentUtc;
                        var expiresIn = (long) (expiresTimeSpan.Value.TotalSeconds + .5);
                        appender.Append(Constants.Parameters.ExpiresIn, expiresIn.ToString(CultureInfo.InvariantCulture));
                    }
                }

                if (!String.IsNullOrEmpty(_authorizeEndpointRequest.State)) {
                    appender.Append(Constants.Parameters.State, _authorizeEndpointRequest.State);
                }

                var authResponseContext = new OpenIdConnectAuthorizationEndpointResponseContext(
                                Context,
                                Options,
                                new AuthenticationTicket(signin.Identity, signin.Properties),
                                _authorizeEndpointRequest,
                                accessToken,
                                null);

                if (_authorizeEndpointRequest.ContainsGrantType(OpenIdConnectResponseTypes.IdToken)) {
                    var idToken = CreateIdToken(
                        authResponseContext.Identity, authResponseContext.Properties,
                        authResponseContext.AuthorizeEndpointRequest.ClientId, authResponseContext.AccessToken,
                        authResponseContext.AuthorizationCode, authResponseContext.Request.Query["nonce"]);

                    appender.Append(Constants.Parameters.IdToken, idToken);
                }

                await Options.Provider.AuthorizationEndpointResponse(authResponseContext);

                foreach (var parameter in authResponseContext.AdditionalResponseParameters) {
                    appender.Append(parameter.Key, parameter.Value.ToString());
                }

                Response.Redirect(appender.ToString());
            }
        }

        private async Task InvokeTokenEndpointAsync() {
            DateTimeOffset currentUtc = Options.SystemClock.UtcNow;
            // remove milliseconds in case they don't round-trip
            currentUtc = currentUtc.Subtract(TimeSpan.FromMilliseconds(currentUtc.Millisecond));

            IFormCollection form = await Request.ReadFormAsync();

            var clientContext = new OpenIdConnectValidateClientAuthenticationContext(
                Context,
                Options,
                form);

            await Options.Provider.ValidateClientAuthentication(clientContext);

            if (!clientContext.IsValidated) {
                _logger.WriteError("clientID is not valid.");
                if (!clientContext.HasError) {
                    clientContext.SetError(Constants.Errors.InvalidClient);
                }
                await SendErrorAsJsonAsync(clientContext);
                return;
            }

            var tokenEndpointRequest = new TokenEndpointRequest(form);

            var validatingContext = new OpenIdConnectValidateTokenRequestContext(Context, Options, tokenEndpointRequest, clientContext);

            AuthenticationTicket ticket = null;
            if (tokenEndpointRequest.IsAuthorizationCodeGrantType) {
                // Authorization Code Grant http://tools.ietf.org/html/rfc6749#section-4.1
                // Access Token Request http://tools.ietf.org/html/rfc6749#section-4.1.3
                ticket = await InvokeTokenEndpointAuthorizationCodeGrantAsync(validatingContext, currentUtc);
            }
            else if (tokenEndpointRequest.IsResourceOwnerPasswordCredentialsGrantType) {
                // Resource Owner Password Credentials Grant http://tools.ietf.org/html/rfc6749#section-4.3
                // Access Token Request http://tools.ietf.org/html/rfc6749#section-4.3.2
                ticket = await InvokeTokenEndpointResourceOwnerPasswordCredentialsGrantAsync(validatingContext, currentUtc);
            }
            else if (tokenEndpointRequest.IsClientCredentialsGrantType) {
                // Client Credentials Grant http://tools.ietf.org/html/rfc6749#section-4.4
                // Access Token Request http://tools.ietf.org/html/rfc6749#section-4.4.2
                ticket = await InvokeTokenEndpointClientCredentialsGrantAsync(validatingContext, currentUtc);
            }
            else if (tokenEndpointRequest.IsRefreshTokenGrantType) {
                // Refreshing an Access Token
                // http://tools.ietf.org/html/rfc6749#section-6
                ticket = await InvokeTokenEndpointRefreshTokenGrantAsync(validatingContext, currentUtc);
            }
            else if (tokenEndpointRequest.IsCustomExtensionGrantType) {
                // Defining New Authorization Grant Types
                // http://tools.ietf.org/html/rfc6749#section-8.3
                ticket = await InvokeTokenEndpointCustomGrantAsync(validatingContext, currentUtc);
            }
            else {
                // Error Response http://tools.ietf.org/html/rfc6749#section-5.2
                // The authorization grant type is not supported by the
                // authorization server.
                _logger.WriteError("grant type is not recognized");
                validatingContext.SetError(Constants.Errors.UnsupportedGrantType);
            }

            if (ticket == null) {
                await SendErrorAsJsonAsync(validatingContext);
                return;
            }

            ticket.Properties.IssuedUtc = currentUtc;
            ticket.Properties.ExpiresUtc = currentUtc.Add(Options.AccessTokenExpireTimeSpan);

            var tokenEndpointContext = new OpenIdConnectTokenEndpointContext(
                Context,
                Options,
                ticket,
                tokenEndpointRequest);

            await Options.Provider.TokenEndpoint(tokenEndpointContext);

            if (tokenEndpointContext.TokenIssued) {
                ticket = new AuthenticationTicket(
                    tokenEndpointContext.Identity,
                    tokenEndpointContext.Properties);
            }
            else {
                _logger.WriteError("Token was not issued to tokenEndpointContext");
                validatingContext.SetError(Constants.Errors.InvalidGrant);
                await SendErrorAsJsonAsync(validatingContext);
                return;
            }

            var accessTokenContext = new AuthenticationTokenCreateContext(
                Context,
                Options.AccessTokenFormat,
                ticket);

            await Options.AccessTokenProvider.CreateAsync(accessTokenContext);

            string accessToken = accessTokenContext.Token;
            if (string.IsNullOrEmpty(accessToken)) {
                accessToken = accessTokenContext.SerializeTicket();
            }
            DateTimeOffset? accessTokenExpiresUtc = ticket.Properties.ExpiresUtc;

            var refreshTokenCreateContext = new AuthenticationTokenCreateContext(
                Context,
                Options.RefreshTokenFormat,
                accessTokenContext.Ticket);
            await Options.RefreshTokenProvider.CreateAsync(refreshTokenCreateContext);
            string refreshToken = refreshTokenCreateContext.Token;

            var tokenEndpointResponseContext = new OpenIdConnectTokenEndpointResponseContext(
                Context,
                Options,
                ticket,
                tokenEndpointRequest,
                accessToken,
                tokenEndpointContext.AdditionalResponseParameters);

            var idToken = CreateIdToken(
                tokenEndpointResponseContext.Identity, tokenEndpointResponseContext.Properties,
                tokenEndpointResponseContext.TokenEndpointRequest.ClientId, tokenEndpointResponseContext.AccessToken);
            tokenEndpointResponseContext.AdditionalResponseParameters.Add(Constants.Parameters.IdToken, idToken);

            await Options.Provider.TokenEndpointResponse(tokenEndpointResponseContext);

            var memory = new MemoryStream();
            byte[] body;
            using (var writer = new JsonTextWriter(new StreamWriter(memory))) {
                writer.WriteStartObject();
                writer.WritePropertyName(Constants.Parameters.AccessToken);
                writer.WriteValue(accessToken);
                writer.WritePropertyName(Constants.Parameters.TokenType);
                writer.WriteValue(Constants.TokenTypes.Bearer);
                if (accessTokenExpiresUtc.HasValue) {
                    TimeSpan? expiresTimeSpan = accessTokenExpiresUtc - currentUtc;
                    var expiresIn = (long) expiresTimeSpan.Value.TotalSeconds;
                    if (expiresIn > 0) {
                        writer.WritePropertyName(Constants.Parameters.ExpiresIn);
                        writer.WriteValue(expiresIn);
                    }
                }
                if (!String.IsNullOrEmpty(refreshToken)) {
                    writer.WritePropertyName(Constants.Parameters.RefreshToken);
                    writer.WriteValue(refreshToken);
                }
                foreach (var additionalResponseParameter in tokenEndpointResponseContext.AdditionalResponseParameters) {
                    writer.WritePropertyName(additionalResponseParameter.Key);
                    writer.WriteValue(additionalResponseParameter.Value);
                }
                writer.WriteEndObject();
                writer.Flush();
                body = memory.ToArray();
            }
            Response.ContentType = "application/json;charset=UTF-8";
            Response.Headers.Set("Cache-Control", "no-cache");
            Response.Headers.Set("Pragma", "no-cache");
            Response.Headers.Set("Expires", "-1");
            Response.ContentLength = memory.ToArray().Length;
            await Response.WriteAsync(body, Request.CallCancelled);
        }

        private async Task<AuthenticationTicket> InvokeTokenEndpointAuthorizationCodeGrantAsync(
            OpenIdConnectValidateTokenRequestContext validatingContext,
            DateTimeOffset currentUtc) {
            TokenEndpointRequest tokenEndpointRequest = validatingContext.TokenRequest;

            var authorizationCodeContext = new AuthenticationTokenReceiveContext(
                Context,
                Options.AuthorizationCodeFormat,
                tokenEndpointRequest.AuthorizationCodeGrant.Code);

            await Options.AuthorizationCodeProvider.ReceiveAsync(authorizationCodeContext);

            AuthenticationTicket ticket = authorizationCodeContext.Ticket;

            if (ticket == null) {
                _logger.WriteError("invalid authorization code");
                validatingContext.SetError(Constants.Errors.InvalidGrant);
                return null;
            }

            if (!ticket.Properties.ExpiresUtc.HasValue ||
                ticket.Properties.ExpiresUtc < currentUtc) {
                _logger.WriteError("expired authorization code");
                validatingContext.SetError(Constants.Errors.InvalidGrant);
                return null;
            }

            string clientId;
            if (!ticket.Properties.Dictionary.TryGetValue(Constants.Extra.ClientId, out clientId) ||
                !String.Equals(clientId, validatingContext.ClientContext.ClientId, StringComparison.Ordinal)) {
                _logger.WriteError("authorization code does not contain matching client_id");
                validatingContext.SetError(Constants.Errors.InvalidGrant);
                return null;
            }

            string redirectUri;
            if (ticket.Properties.Dictionary.TryGetValue(Constants.Extra.RedirectUri, out redirectUri)) {
                ticket.Properties.Dictionary.Remove(Constants.Extra.RedirectUri);
                if (!String.Equals(redirectUri, tokenEndpointRequest.AuthorizationCodeGrant.RedirectUri, StringComparison.Ordinal)) {
                    _logger.WriteError("authorization code does not contain matching redirect_uri");
                    validatingContext.SetError(Constants.Errors.InvalidGrant);
                    return null;
                }
            }

            await Options.Provider.ValidateTokenRequest(validatingContext);

            var grantContext = new OpenIdConnectGrantAuthorizationCodeContext(
                Context, Options, ticket);

            if (validatingContext.IsValidated) {
                await Options.Provider.GrantAuthorizationCode(grantContext);
            }

            return ReturnOutcome(
                validatingContext,
                grantContext,
                grantContext.Ticket,
                Constants.Errors.InvalidGrant);
        }

        private async Task<AuthenticationTicket> InvokeTokenEndpointResourceOwnerPasswordCredentialsGrantAsync(
            OpenIdConnectValidateTokenRequestContext validatingContext,
            DateTimeOffset currentUtc) {
            TokenEndpointRequest tokenEndpointRequest = validatingContext.TokenRequest;

            await Options.Provider.ValidateTokenRequest(validatingContext);

            var grantContext = new OpenIdConnectGrantResourceOwnerCredentialsContext(
                Context,
                Options,
                validatingContext.ClientContext.ClientId,
                tokenEndpointRequest.ResourceOwnerPasswordCredentialsGrant.UserName,
                tokenEndpointRequest.ResourceOwnerPasswordCredentialsGrant.Password,
                tokenEndpointRequest.ResourceOwnerPasswordCredentialsGrant.Scope);

            if (validatingContext.IsValidated) {
                await Options.Provider.GrantResourceOwnerCredentials(grantContext);
            }

            return ReturnOutcome(
                validatingContext,
                grantContext,
                grantContext.Ticket,
                Constants.Errors.InvalidGrant);
        }

        private async Task<AuthenticationTicket> InvokeTokenEndpointClientCredentialsGrantAsync(
            OpenIdConnectValidateTokenRequestContext validatingContext,
            DateTimeOffset currentUtc) {
            TokenEndpointRequest tokenEndpointRequest = validatingContext.TokenRequest;

            await Options.Provider.ValidateTokenRequest(validatingContext);
            if (!validatingContext.IsValidated) {
                return null;
            }

            var grantContext = new OpenIdConnectGrantClientCredentialsContext(
                Context,
                Options,
                validatingContext.ClientContext.ClientId,
                tokenEndpointRequest.ClientCredentialsGrant.Scope);

            await Options.Provider.GrantClientCredentials(grantContext);

            return ReturnOutcome(
                validatingContext,
                grantContext,
                grantContext.Ticket,
                Constants.Errors.UnauthorizedClient);
        }

        private async Task<AuthenticationTicket> InvokeTokenEndpointRefreshTokenGrantAsync(
            OpenIdConnectValidateTokenRequestContext validatingContext,
            DateTimeOffset currentUtc) {
            TokenEndpointRequest tokenEndpointRequest = validatingContext.TokenRequest;

            var refreshTokenContext = new AuthenticationTokenReceiveContext(
                Context,
                Options.RefreshTokenFormat,
                tokenEndpointRequest.RefreshTokenGrant.RefreshToken);

            await Options.RefreshTokenProvider.ReceiveAsync(refreshTokenContext);

            AuthenticationTicket ticket = refreshTokenContext.Ticket;

            if (ticket == null) {
                _logger.WriteError("invalid refresh token");
                validatingContext.SetError(Constants.Errors.InvalidGrant);
                return null;
            }

            if (!ticket.Properties.ExpiresUtc.HasValue ||
                ticket.Properties.ExpiresUtc < currentUtc) {
                _logger.WriteError("expired refresh token");
                validatingContext.SetError(Constants.Errors.InvalidGrant);
                return null;
            }

            await Options.Provider.ValidateTokenRequest(validatingContext);

            var grantContext = new OpenIdConnectGrantRefreshTokenContext(Context, Options, ticket, validatingContext.ClientContext.ClientId);

            if (validatingContext.IsValidated) {
                await Options.Provider.GrantRefreshToken(grantContext);
            }

            return ReturnOutcome(
                validatingContext,
                grantContext,
                grantContext.Ticket,
                Constants.Errors.InvalidGrant);
        }

        private async Task<AuthenticationTicket> InvokeTokenEndpointCustomGrantAsync(
            OpenIdConnectValidateTokenRequestContext validatingContext,
            DateTimeOffset currentUtc) {
            TokenEndpointRequest tokenEndpointRequest = validatingContext.TokenRequest;

            await Options.Provider.ValidateTokenRequest(validatingContext);

            var grantContext = new OpenIdConnectGrantCustomExtensionContext(
                Context,
                Options,
                validatingContext.ClientContext.ClientId,
                tokenEndpointRequest.GrantType,
                tokenEndpointRequest.CustomExtensionGrant.Parameters);

            if (validatingContext.IsValidated) {
                await Options.Provider.GrantCustomExtension(grantContext);
            }

            return ReturnOutcome(
                validatingContext,
                grantContext,
                grantContext.Ticket,
                Constants.Errors.UnsupportedGrantType);
        }

        private string CreateIdToken(ClaimsIdentity identity, AuthenticationProperties authProperties, string clientId, string accessToken = null, string authorizationCode = null, string nonce = null) {
            var inputClaims = identity.Claims;
            var outputClaims = Options.ServerClaimsMapper(inputClaims).ToList();

            var hashGenerator = new OpenIdConnectHashGenerator();

            if (!string.IsNullOrEmpty(authorizationCode)) {
                var cHash = hashGenerator.GenerateHash(authorizationCode, Options.SigningCredentials.DigestAlgorithm);
                outputClaims.Add(new Claim(JwtRegisteredClaimNames.CHash, cHash));
            }

            if (!string.IsNullOrEmpty(accessToken)) {
                var atHash = hashGenerator.GenerateHash(accessToken, Options.SigningCredentials.DigestAlgorithm);
                outputClaims.Add(new Claim("at_hash", atHash));
            }

            if (!string.IsNullOrEmpty(nonce)) {
                outputClaims.Add(new Claim(JwtRegisteredClaimNames.Nonce, nonce));
            }

            var iat = EpochTime.GetIntDate(Options.SystemClock.UtcNow.UtcDateTime).ToString();
            outputClaims.Add(new Claim("iat", iat));

            DateTimeOffset notBefore = Options.SystemClock.UtcNow;
            DateTimeOffset expires = notBefore.Add(Options.IdTokenExpireTimeSpan);

            string notBeforeString;
            if (authProperties.Dictionary.TryGetValue("IdTokenIssuedUtc", out notBeforeString)) {
                DateTimeOffset value;
                if (DateTimeOffset.TryParseExact(notBeforeString, "r", CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out value))
                    notBefore = value;
            }

            string expiresString;
            if (authProperties.Dictionary.TryGetValue("IdTokenExpiresUtc", out expiresString)) {
                DateTimeOffset value;
                if (DateTimeOffset.TryParseExact(expiresString, "r", CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out value))
                    expires = value;
            }

            var jwt = Options.TokenHandler.CreateToken(
                issuer: Options.IssuerName,
                signingCredentials: Options.SigningCredentials,
                audience: clientId,
                notBefore: notBefore.UtcDateTime,
                expires: expires.UtcDateTime,
                signatureProvider: Options.SignatureProvider
            );

            jwt.Payload.AddClaims(outputClaims);

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

        [SuppressMessage("Microsoft.Reliability", "CA2000:Dispose objects before losing scope", Justification = "The MemoryStream is Disposed by the StreamWriter")]
        private Task SendErrorAsJsonAsync(
            BaseValidatingContext<OpenIdConnectServerOptions> validatingContext) {
            string error = validatingContext.HasError ? validatingContext.Error : Constants.Errors.InvalidRequest;
            string errorDescription = validatingContext.HasError ? validatingContext.ErrorDescription : null;
            string errorUri = validatingContext.HasError ? validatingContext.ErrorUri : null;

            var memory = new MemoryStream();
            byte[] body;
            using (var writer = new JsonTextWriter(new StreamWriter(memory))) {
                writer.WriteStartObject();
                writer.WritePropertyName(Constants.Parameters.Error);
                writer.WriteValue(error);
                if (!string.IsNullOrEmpty(errorDescription)) {
                    writer.WritePropertyName(Constants.Parameters.ErrorDescription);
                    writer.WriteValue(errorDescription);
                }
                if (!string.IsNullOrEmpty(errorUri)) {
                    writer.WritePropertyName(Constants.Parameters.ErrorUri);
                    writer.WriteValue(errorUri);
                }
                writer.WriteEndObject();
                writer.Flush();
                body = memory.ToArray();
            }
            Response.StatusCode = 400;
            Response.ContentType = "application/json;charset=UTF-8";
            Response.Headers.Set("Cache-Control", "no-cache");
            Response.Headers.Set("Pragma", "no-cache");
            Response.Headers.Set("Expires", "-1");
            Response.Headers.Set("Content-Length", body.Length.ToString(CultureInfo.InvariantCulture));
            return Response.WriteAsync(body, Request.CallCancelled);
        }

        private Task<bool> SendErrorRedirectAsync(
            OpenIdConnectValidateClientRedirectUriContext clientContext,
            BaseValidatingContext<OpenIdConnectServerOptions> validatingContext) {
            if (clientContext == null) {
                throw new ArgumentNullException("clientContext");
            }

            string error = validatingContext.HasError ? validatingContext.Error : Constants.Errors.InvalidRequest;
            string errorDescription = validatingContext.HasError ? validatingContext.ErrorDescription : null;
            string errorUri = validatingContext.HasError ? validatingContext.ErrorUri : null;

            if (!clientContext.IsValidated) {
                // write error in response body if client_id or redirect_uri have not been validated
                return SendErrorPageAsync(error, errorDescription, errorUri);
            }

            // redirect with error if client_id and redirect_uri have been validated
            string location = WebUtilities.AddQueryString(clientContext.RedirectUri, Constants.Parameters.Error, error);
            if (!string.IsNullOrEmpty(errorDescription)) {
                location = WebUtilities.AddQueryString(location, Constants.Parameters.ErrorDescription, errorDescription);
            }
            if (!string.IsNullOrEmpty(errorUri)) {
                location = WebUtilities.AddQueryString(location, Constants.Parameters.ErrorUri, errorUri);
            }
            Response.Redirect(location);
            // request is handled, does not pass on to application
            return Task.FromResult(true);
        }

        private async Task<bool> SendErrorPageAsync(string error, string errorDescription, string errorUri) {
            Response.StatusCode = 400;
            Response.Headers.Set("Cache-Control", "no-cache");
            Response.Headers.Set("Pragma", "no-cache");
            Response.Headers.Set("Expires", "-1");

            if (Options.ApplicationCanDisplayErrors) {
                Context.Set("oauth.Error", error);
                Context.Set("oauth.ErrorDescription", errorDescription);
                Context.Set("oauth.ErrorUri", errorUri);
                // request is not handled - pass through to application for rendering
                return false;
            }

            var memory = new MemoryStream();
            byte[] body;
            using (var writer = new StreamWriter(memory)) {
                writer.WriteLine("error: {0}", error);
                if (!string.IsNullOrEmpty(errorDescription)) {
                    writer.WriteLine("error_description: {0}", errorDescription);
                }
                if (!string.IsNullOrEmpty(errorUri)) {
                    writer.WriteLine("error_uri: {0}", errorUri);
                }
                writer.Flush();
                body = memory.ToArray();
            }

            Response.ContentType = "text/plain;charset=UTF-8";
            Response.Headers.Set("Content-Length", body.Length.ToString(CultureInfo.InvariantCulture));
            await Response.WriteAsync(body, Request.CallCancelled);
            // request is handled, does not pass on to application
            return true;
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
