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
    /// Represents a generic OpenID Connect response.
    /// </summary>
    /// <remarks>
    /// Security notice: developers instantiating this type are responsible of ensuring that the
    /// imported parameters are safe and won't cause the resulting message to grow abnormally,
    /// which may result in an excessive memory consumption and a potential denial of service.
    /// </remarks>
    [DebuggerDisplay("Parameters: {Parameters.Count}")]
    [JsonConverter(typeof(OpenIdConnectConverter))]
    public class OpenIdConnectResponse : OpenIdConnectMessage
    {
        /// <summary>
        /// Initializes a new OpenID Connect response.
        /// </summary>
        public OpenIdConnectResponse()
            : base() { }

        /// <summary>
        /// Initializes a new OpenID Connect response.
        /// </summary>
        /// <param name="parameters">The response parameters.</param>
        public OpenIdConnectResponse([NotNull] IEnumerable<KeyValuePair<string, JToken>> parameters)
            : base(parameters) { }

        /// <summary>
        /// Initializes a new OpenID Connect response.
        /// </summary>
        /// <param name="parameters">The response parameters.</param>
        public OpenIdConnectResponse([NotNull] IEnumerable<KeyValuePair<string, OpenIdConnectParameter>> parameters)
            : base(parameters) { }

        /// <summary>
        /// Initializes a new OpenID Connect response.
        /// </summary>
        /// <param name="parameters">The response parameters.</param>
        public OpenIdConnectResponse([NotNull] IEnumerable<KeyValuePair<string, string>> parameters)
            : base(parameters) { }

        /// <summary>
        /// Initializes a new OpenID Connect response.
        /// </summary>
        /// <param name="parameters">The response parameters.</param>
        public OpenIdConnectResponse([NotNull] IEnumerable<KeyValuePair<string, string[]>> parameters)
            : base(parameters) { }

        /// <summary>
        /// Initializes a new OpenID Connect response.
        /// </summary>
        /// <param name="parameters">The response parameters.</param>
        public OpenIdConnectResponse([NotNull] IEnumerable<KeyValuePair<string, StringValues>> parameters)
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
        /// Gets or sets the "code" parameter.
        /// </summary>
        public string Code
        {
            get => (string) GetParameter(OpenIdConnectConstants.Parameters.Code);
            set => SetParameter(OpenIdConnectConstants.Parameters.Code, value);
        }

        /// <summary>
        /// Gets or sets the "error" parameter.
        /// </summary>
        public string Error
        {
            get => (string) GetParameter(OpenIdConnectConstants.Parameters.Error);
            set => SetParameter(OpenIdConnectConstants.Parameters.Error, value);
        }

        /// <summary>
        /// Gets or sets the "error_description" parameter.
        /// </summary>
        public string ErrorDescription
        {
            get => (string) GetParameter(OpenIdConnectConstants.Parameters.ErrorDescription);
            set => SetParameter(OpenIdConnectConstants.Parameters.ErrorDescription, value);
        }

        /// <summary>
        /// Gets or sets the "error_uri" parameter.
        /// </summary>
        public string ErrorUri
        {
            get => (string) GetParameter(OpenIdConnectConstants.Parameters.ErrorUri);
            set => SetParameter(OpenIdConnectConstants.Parameters.ErrorUri, value);
        }

        /// <summary>
        /// Gets or sets the "expires_in" parameter.
        /// </summary>
        public long? ExpiresIn
        {
            get => (long?) GetParameter(OpenIdConnectConstants.Parameters.ExpiresIn);
            set => SetParameter(OpenIdConnectConstants.Parameters.ExpiresIn, value);
        }

        /// <summary>
        /// Gets or sets the "id_token" parameter.
        /// </summary>
        public string IdToken
        {
            get => (string) GetParameter(OpenIdConnectConstants.Parameters.IdToken);
            set => SetParameter(OpenIdConnectConstants.Parameters.IdToken, value);
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
        /// Gets or sets the "token_type" parameter.
        /// </summary>
        public string TokenType
        {
            get => (string) GetParameter(OpenIdConnectConstants.Parameters.TokenType);
            set => SetParameter(OpenIdConnectConstants.Parameters.TokenType, value);
        }
    }
}
