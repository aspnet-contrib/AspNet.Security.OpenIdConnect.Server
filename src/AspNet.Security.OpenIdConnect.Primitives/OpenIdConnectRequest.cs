/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System.Collections.Generic;
using System.Diagnostics;
using JetBrains.Annotations;
using Microsoft.Extensions.Primitives;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace AspNet.Security.OpenIdConnect.Primitives
{
    /// <summary>
    /// Represents a generic OpenID Connect request.
    /// </summary>
    /// <remarks>
    /// Security notice: developers instantiating this type are responsible of ensuring that the
    /// imported parameters are safe and won't cause the resulting message to grow abnormally,
    /// which may result in an excessive memory consumption and a potential denial of service.
    /// </remarks>
    [DebuggerDisplay("Parameters: {Parameters.Count}")]
    [JsonConverter(typeof(OpenIdConnectConverter))]
    public class OpenIdConnectRequest : OpenIdConnectMessage
    {
        /// <summary>
        /// Initializes a new OpenID Connect request.
        /// </summary>
        public OpenIdConnectRequest()
            : base() { }

        /// <summary>
        /// Initializes a new OpenID Connect request.
        /// </summary>
        /// <param name="parameters">The request parameters.</param>
        public OpenIdConnectRequest([NotNull] IEnumerable<KeyValuePair<string, JToken>> parameters)
            : base(parameters) { }

        /// <summary>
        /// Initializes a new OpenID Connect request.
        /// </summary>
        /// <param name="parameters">The request parameters.</param>
        public OpenIdConnectRequest([NotNull] IEnumerable<KeyValuePair<string, OpenIdConnectParameter>> parameters)
            : base(parameters) { }

        /// <summary>
        /// Initializes a new OpenID Connect request.
        /// </summary>
        /// <param name="parameters">The request parameters.</param>
        public OpenIdConnectRequest([NotNull] IEnumerable<KeyValuePair<string, string>> parameters)
            : base(parameters) { }

        /// <summary>
        /// Initializes a new OpenID Connect request.
        /// </summary>
        /// <param name="parameters">The request parameters.</param>
        public OpenIdConnectRequest([NotNull] IEnumerable<KeyValuePair<string, string[]>> parameters)
            : base(parameters) { }

        /// <summary>
        /// Initializes a new OpenID Connect request.
        /// </summary>
        /// <param name="parameters">The request parameters.</param>
        public OpenIdConnectRequest([NotNull] IEnumerable<KeyValuePair<string, StringValues>> parameters)
            : base(parameters) { }

        /// <summary>
        /// Gets or sets the "access_token" parameter.
        /// </summary>
        public string AccessToken
        {
            get => (string) GetParameter(OpenIdConnectConstants.Parameters.AccessToken);
            set => SetParameter(OpenIdConnectConstants.Parameters.AccessToken, value);
        }

        /// <summary>
        /// Gets or sets the "acr_values" parameter.
        /// </summary>
        public string AcrValues
        {
            get => (string) GetParameter(OpenIdConnectConstants.Parameters.AcrValues);
            set => SetParameter(OpenIdConnectConstants.Parameters.AcrValues, value);
        }

        /// <summary>
        /// Gets or sets the "assertion" parameter.
        /// </summary>
        public string Assertion
        {
            get => (string) GetParameter(OpenIdConnectConstants.Parameters.Assertion);
            set => SetParameter(OpenIdConnectConstants.Parameters.Assertion, value);
        }

        /// <summary>
        /// Gets or sets the "audience" parameters.
        /// </summary>
        public string[] Audiences
        {
            get => (string[]) GetParameter(OpenIdConnectConstants.Parameters.Audience);
            set => SetParameter(OpenIdConnectConstants.Parameters.Audience, value);
        }

        /// <summary>
        /// Gets or sets the "claims" parameter.
        /// </summary>
        public JObject Claims
        {
            get => (JObject) GetParameter(OpenIdConnectConstants.Parameters.Claims);
            set => SetParameter(OpenIdConnectConstants.Parameters.Claims, value);
        }

        /// <summary>
        /// Gets or sets the "claims_locales" parameter.
        /// </summary>
        public string ClaimsLocales
        {
            get => (string) GetParameter(OpenIdConnectConstants.Parameters.ClaimsLocales);
            set => SetParameter(OpenIdConnectConstants.Parameters.ClaimsLocales, value);
        }

        /// <summary>
        /// Gets or sets the "client_assertion" parameter.
        /// </summary>
        public string ClientAssertion
        {
            get => (string) GetParameter(OpenIdConnectConstants.Parameters.ClientAssertion);
            set => SetParameter(OpenIdConnectConstants.Parameters.ClientAssertion, value);
        }

        /// <summary>
        /// Gets or sets the "client_assertion_type" parameter.
        /// </summary>
        public string ClientAssertionType
        {
            get => (string) GetParameter(OpenIdConnectConstants.Parameters.ClientAssertionType);
            set => SetParameter(OpenIdConnectConstants.Parameters.ClientAssertionType, value);
        }

        /// <summary>
        /// Gets or sets the "client_id" parameter.
        /// </summary>
        public string ClientId
        {
            get => (string) GetParameter(OpenIdConnectConstants.Parameters.ClientId);
            set => SetParameter(OpenIdConnectConstants.Parameters.ClientId, value);
        }

        /// <summary>
        /// Gets or sets the "client_secret" parameter.
        /// </summary>
        public string ClientSecret
        {
            get => (string) GetParameter(OpenIdConnectConstants.Parameters.ClientSecret);
            set => SetParameter(OpenIdConnectConstants.Parameters.ClientSecret, value);
        }

        /// <summary>
        /// Gets or sets the "code" parameter.
        /// </summary>
        public string Code
        {
            get => (string) GetParameter(OpenIdConnectConstants.Parameters.Code);
            set => SetParameter(OpenIdConnectConstants.Parameters.Code, value);
        }

        /// <summary>
        /// Gets or sets the "code_challenge" parameter.
        /// </summary>
        public string CodeChallenge
        {
            get => (string) GetParameter(OpenIdConnectConstants.Parameters.CodeChallenge);
            set => SetParameter(OpenIdConnectConstants.Parameters.CodeChallenge, value);
        }

        /// <summary>
        /// Gets or sets the "code_challenge_method" parameter.
        /// </summary>
        public string CodeChallengeMethod
        {
            get => (string) GetParameter(OpenIdConnectConstants.Parameters.CodeChallengeMethod);
            set => SetParameter(OpenIdConnectConstants.Parameters.CodeChallengeMethod, value);
        }

        /// <summary>
        /// Gets or sets the "code_verifier" parameter.
        /// </summary>
        public string CodeVerifier
        {
            get => (string) GetParameter(OpenIdConnectConstants.Parameters.CodeVerifier);
            set => SetParameter(OpenIdConnectConstants.Parameters.CodeVerifier, value);
        }

        /// <summary>
        /// Gets or sets the "display" parameter.
        /// </summary>
        public string Display
        {
            get => (string) GetParameter(OpenIdConnectConstants.Parameters.Display);
            set => SetParameter(OpenIdConnectConstants.Parameters.Display, value);
        }

        /// <summary>
        /// Gets or sets the "grant_type" parameter.
        /// </summary>
        public string GrantType
        {
            get => (string) GetParameter(OpenIdConnectConstants.Parameters.GrantType);
            set => SetParameter(OpenIdConnectConstants.Parameters.GrantType, value);
        }

        /// <summary>
        /// Gets or sets the "identity_provider" parameter.
        /// </summary>
        public string IdentityProvider
        {
            get => (string) GetParameter(OpenIdConnectConstants.Parameters.IdentityProvider);
            set => SetParameter(OpenIdConnectConstants.Parameters.IdentityProvider, value);
        }

        /// <summary>
        /// Gets or sets the "id_token_hint" parameter.
        /// </summary>
        public string IdTokenHint
        {
            get => (string) GetParameter(OpenIdConnectConstants.Parameters.IdTokenHint);
            set => SetParameter(OpenIdConnectConstants.Parameters.IdTokenHint, value);
        }

        /// <summary>
        /// Gets or sets the "login_hint" parameter.
        /// </summary>
        public string LoginHint
        {
            get => (string) GetParameter(OpenIdConnectConstants.Parameters.LoginHint);
            set => SetParameter(OpenIdConnectConstants.Parameters.LoginHint, value);
        }

        /// <summary>
        /// Gets or sets the "max_age" parameter.
        /// </summary>
        public long? MaxAge
        {
            get => (long?) GetParameter(OpenIdConnectConstants.Parameters.MaxAge);
            set => SetParameter(OpenIdConnectConstants.Parameters.MaxAge, value);
        }

        /// <summary>
        /// Gets or sets the "nonce" parameter.
        /// </summary>
        public string Nonce
        {
            get => (string) GetParameter(OpenIdConnectConstants.Parameters.Nonce);
            set => SetParameter(OpenIdConnectConstants.Parameters.Nonce, value);
        }

        /// <summary>
        /// Gets or sets the "password" parameter.
        /// </summary>
        public string Password
        {
            get => (string) GetParameter(OpenIdConnectConstants.Parameters.Password);
            set => SetParameter(OpenIdConnectConstants.Parameters.Password, value);
        }

        /// <summary>
        /// Gets or sets the "post_logout_redirect_uri" parameter.
        /// </summary>
        public string PostLogoutRedirectUri
        {
            get => (string) GetParameter(OpenIdConnectConstants.Parameters.PostLogoutRedirectUri);
            set => SetParameter(OpenIdConnectConstants.Parameters.PostLogoutRedirectUri, value);
        }

        /// <summary>
        /// Gets or sets the "prompt" parameter.
        /// </summary>
        public string Prompt
        {
            get => (string) GetParameter(OpenIdConnectConstants.Parameters.Prompt);
            set => SetParameter(OpenIdConnectConstants.Parameters.Prompt, value);
        }

        /// <summary>
        /// Gets or sets the "redirect_uri" parameter.
        /// </summary>
        public string RedirectUri
        {
            get => (string) GetParameter(OpenIdConnectConstants.Parameters.RedirectUri);
            set => SetParameter(OpenIdConnectConstants.Parameters.RedirectUri, value);
        }

        /// <summary>
        /// Gets or sets the "refresh_token" parameter.
        /// </summary>
        public string RefreshToken
        {
            get => (string) GetParameter(OpenIdConnectConstants.Parameters.RefreshToken);
            set => SetParameter(OpenIdConnectConstants.Parameters.RefreshToken, value);
        }

        /// <summary>
        /// Gets or sets the "request" parameter.
        /// </summary>
        public string Request
        {
            get => (string) GetParameter(OpenIdConnectConstants.Parameters.Request);
            set => SetParameter(OpenIdConnectConstants.Parameters.Request, value);
        }

        /// <summary>
        /// Gets or sets the "request_id" parameter.
        /// </summary>
        public string RequestId
        {
            get => (string) GetParameter(OpenIdConnectConstants.Parameters.RequestId);
            set => SetParameter(OpenIdConnectConstants.Parameters.RequestId, value);
        }

        /// <summary>
        /// Gets or sets the "request_uri" parameter.
        /// </summary>
        public string RequestUri
        {
            get => (string) GetParameter(OpenIdConnectConstants.Parameters.RequestUri);
            set => SetParameter(OpenIdConnectConstants.Parameters.RequestUri, value);
        }

        /// <summary>
        /// Gets or sets the "resource" parameters.
        /// </summary>
        public string[] Resources
        {
            get => (string[]) GetParameter(OpenIdConnectConstants.Parameters.Resource);
            set => SetParameter(OpenIdConnectConstants.Parameters.Resource, value);
        }

        /// <summary>
        /// Gets or sets the "response_mode" parameter.
        /// </summary>
        public string ResponseMode
        {
            get => (string) GetParameter(OpenIdConnectConstants.Parameters.ResponseMode);
            set => SetParameter(OpenIdConnectConstants.Parameters.ResponseMode, value);
        }

        /// <summary>
        /// Gets or sets the "response_type" parameter.
        /// </summary>
        public string ResponseType
        {
            get => (string) GetParameter(OpenIdConnectConstants.Parameters.ResponseType);
            set => SetParameter(OpenIdConnectConstants.Parameters.ResponseType, value);
        }

        /// <summary>
        /// Gets or sets the "scope" parameter.
        /// </summary>
        public string Scope
        {
            get => (string) GetParameter(OpenIdConnectConstants.Parameters.Scope);
            set => SetParameter(OpenIdConnectConstants.Parameters.Scope, value);
        }

        /// <summary>
        /// Gets or sets the "state" parameter.
        /// </summary>
        public string State
        {
            get => (string) GetParameter(OpenIdConnectConstants.Parameters.State);
            set => SetParameter(OpenIdConnectConstants.Parameters.State, value);
        }

        /// <summary>
        /// Gets or sets the "token" parameter.
        /// </summary>
        public string Token
        {
            get => (string) GetParameter(OpenIdConnectConstants.Parameters.Token);
            set => SetParameter(OpenIdConnectConstants.Parameters.Token, value);
        }

        /// <summary>
        /// Gets or sets the "token_type_hint" parameter.
        /// </summary>
        public string TokenTypeHint
        {
            get => (string) GetParameter(OpenIdConnectConstants.Parameters.TokenTypeHint);
            set => SetParameter(OpenIdConnectConstants.Parameters.TokenTypeHint, value);
        }

        /// <summary>
        /// Gets or sets the "registration" parameter.
        /// </summary>
        public JObject Registration
        {
            get => (JObject) GetParameter(OpenIdConnectConstants.Parameters.Registration);
            set => SetParameter(OpenIdConnectConstants.Parameters.Registration, value);
        }

        /// <summary>
        /// Gets or sets the "ui_locales" parameter.
        /// </summary>
        public string UiLocales
        {
            get => (string) GetParameter(OpenIdConnectConstants.Parameters.UiLocales);
            set => SetParameter(OpenIdConnectConstants.Parameters.UiLocales, value);
        }

        /// <summary>
        /// Gets or sets the "username" parameter.
        /// </summary>
        public string Username
        {
            get => (string) GetParameter(OpenIdConnectConstants.Parameters.Username);
            set => SetParameter(OpenIdConnectConstants.Parameters.Username, value);
        }
    }
}
