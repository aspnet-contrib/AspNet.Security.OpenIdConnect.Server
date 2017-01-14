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

namespace AspNet.Security.OpenIdConnect.Primitives {
    /// <summary>
    /// Represents a generic OpenID Connect response.
    /// </summary>
    [DebuggerDisplay("Parameters: {Parameters.Count}")]
    [JsonConverter(typeof(OpenIdConnectConverter))]
    public class OpenIdConnectResponse : OpenIdConnectMessage {
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
        public string AccessToken {
            get { return (string) GetParameter(OpenIdConnectConstants.Parameters.AccessToken); }
            set { SetParameter(OpenIdConnectConstants.Parameters.AccessToken, value); }
        }

        /// <summary>
        /// Gets or sets the "code" parameter.
        /// </summary>
        public string Code {
            get { return (string) GetParameter(OpenIdConnectConstants.Parameters.Code); }
            set { SetParameter(OpenIdConnectConstants.Parameters.Code, value); }
        }

        /// <summary>
        /// Gets or sets the "error" parameter.
        /// </summary>
        public string Error {
            get { return (string) GetParameter(OpenIdConnectConstants.Parameters.Error); }
            set { SetParameter(OpenIdConnectConstants.Parameters.Error, value); }
        }

        /// <summary>
        /// Gets or sets the "error_description" parameter.
        /// </summary>
        public string ErrorDescription {
            get { return (string) GetParameter(OpenIdConnectConstants.Parameters.ErrorDescription); }
            set { SetParameter(OpenIdConnectConstants.Parameters.ErrorDescription, value); }
        }

        /// <summary>
        /// Gets or sets the "error_uri" parameter.
        /// </summary>
        public string ErrorUri {
            get { return (string) GetParameter(OpenIdConnectConstants.Parameters.ErrorUri); }
            set { SetParameter(OpenIdConnectConstants.Parameters.ErrorUri, value); }
        }

        /// <summary>
        /// Gets or sets the "expires_in" parameter.
        /// </summary>
        public long? ExpiresIn {
            get { return (long?) GetParameter(OpenIdConnectConstants.Parameters.ExpiresIn); }
            set { SetParameter(OpenIdConnectConstants.Parameters.ExpiresIn, value); }
        }

        /// <summary>
        /// Gets or sets the "id_token" parameter.
        /// </summary>
        public string IdToken {
            get { return (string) GetParameter(OpenIdConnectConstants.Parameters.IdToken); }
            set { SetParameter(OpenIdConnectConstants.Parameters.IdToken, value); }
        }

        /// <summary>
        /// Gets or sets the "post_logout_redirect_uri" parameter.
        /// </summary>
        public string PostLogoutRedirectUri {
            get { return (string) GetParameter(OpenIdConnectConstants.Parameters.PostLogoutRedirectUri); }
            set { SetParameter(OpenIdConnectConstants.Parameters.PostLogoutRedirectUri, value); }
        }

        /// <summary>
        /// Gets or sets the "redirect_uri" parameter.
        /// </summary>
        public string RedirectUri {
            get { return (string) GetParameter(OpenIdConnectConstants.Parameters.RedirectUri); }
            set { SetParameter(OpenIdConnectConstants.Parameters.RedirectUri, value); }
        }

        /// <summary>
        /// Gets or sets the "refresh_token" parameter.
        /// </summary>
        public string RefreshToken {
            get { return (string) GetParameter(OpenIdConnectConstants.Parameters.RefreshToken); }
            set { SetParameter(OpenIdConnectConstants.Parameters.RefreshToken, value); }
        }

        /// <summary>
        /// Gets or sets the "resource" parameter.
        /// </summary>
        public string Resource {
            get { return (string) GetParameter(OpenIdConnectConstants.Parameters.Resource); }
            set { SetParameter(OpenIdConnectConstants.Parameters.Resource, value); }
        }

        /// <summary>
        /// Gets or sets the "scope" parameter.
        /// </summary>
        public string Scope {
            get { return (string) GetParameter(OpenIdConnectConstants.Parameters.Scope); }
            set { SetParameter(OpenIdConnectConstants.Parameters.Scope, value); }
        }

        /// <summary>
        /// Gets or sets the "state" parameter.
        /// </summary>
        public string State {
            get { return (string) GetParameter(OpenIdConnectConstants.Parameters.State); }
            set { SetParameter(OpenIdConnectConstants.Parameters.State, value); }
        }

        /// <summary>
        /// Gets or sets the "token_type" parameter.
        /// </summary>
        public string TokenType {
            get { return (string) GetParameter(OpenIdConnectConstants.Parameters.TokenType); }
            set { SetParameter(OpenIdConnectConstants.Parameters.TokenType, value); }
        }
    }
}
