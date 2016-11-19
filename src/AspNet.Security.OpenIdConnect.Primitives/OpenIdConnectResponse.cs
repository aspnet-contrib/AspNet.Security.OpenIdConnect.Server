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
    [JsonObject(MemberSerialization = MemberSerialization.OptIn)]
    public class OpenIdConnectResponse : OpenIdConnectMessage {
        /// <summary>
        /// Initializes a new OpenID Connect response.
        /// </summary>
        public OpenIdConnectResponse()
            : base() { }

        /// <summary>
        /// Initializes a new OpenID Connect response.
        /// </summary>
        /// <param name="payload">The response payload.</param>
        public OpenIdConnectResponse([NotNull] JObject payload)
            : base(payload) { }

        /// <summary>
        /// Initializes a new OpenID Connect response.
        /// </summary>
        /// <param name="parameters">The response parameters.</param>
        public OpenIdConnectResponse([NotNull] IDictionary<string, string> parameters)
            : base(parameters) { }

        /// <summary>
        /// Initializes a new OpenID Connect response.
        /// </summary>
        /// <param name="parameters">The response parameters.</param>
        public OpenIdConnectResponse([NotNull] IDictionary<string, JToken> parameters)
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
            get { return GetParameter<string>(OpenIdConnectConstants.Parameters.AccessToken); }
            set { SetParameter(OpenIdConnectConstants.Parameters.AccessToken, value); }
        }

        /// <summary>
        /// Gets or sets the "code" parameter.
        /// </summary>
        public string Code {
            get { return GetParameter<string>(OpenIdConnectConstants.Parameters.Code); }
            set { SetParameter(OpenIdConnectConstants.Parameters.Code, value); }
        }

        /// <summary>
        /// Gets or sets the "error" parameter.
        /// </summary>
        public string Error {
            get { return GetParameter<string>(OpenIdConnectConstants.Parameters.Error); }
            set { SetParameter(OpenIdConnectConstants.Parameters.Error, value); }
        }

        /// <summary>
        /// Gets or sets the "error_description" parameter.
        /// </summary>
        public string ErrorDescription {
            get { return GetParameter<string>(OpenIdConnectConstants.Parameters.ErrorDescription); }
            set { SetParameter(OpenIdConnectConstants.Parameters.ErrorDescription, value); }
        }

        /// <summary>
        /// Gets or sets the "error_uri" parameter.
        /// </summary>
        public string ErrorUri {
            get { return GetParameter<string>(OpenIdConnectConstants.Parameters.ErrorUri); }
            set { SetParameter(OpenIdConnectConstants.Parameters.ErrorUri, value); }
        }

        /// <summary>
        /// Gets or sets the "expires_in" parameter.
        /// </summary>
        public long? ExpiresIn {
            get { return GetParameter<long?>(OpenIdConnectConstants.Parameters.ExpiresIn); }
            set { SetParameter(OpenIdConnectConstants.Parameters.ExpiresIn, value); }
        }

        /// <summary>
        /// Gets or sets the "id_token" parameter.
        /// </summary>
        public string IdToken {
            get { return GetParameter<string>(OpenIdConnectConstants.Parameters.IdToken); }
            set { SetParameter(OpenIdConnectConstants.Parameters.IdToken, value); }
        }

        /// <summary>
        /// Gets or sets the "post_logout_redirect_uri" parameter.
        /// </summary>
        public string PostLogoutRedirectUri {
            get { return GetParameter<string>(OpenIdConnectConstants.Parameters.PostLogoutRedirectUri); }
            set { SetParameter(OpenIdConnectConstants.Parameters.PostLogoutRedirectUri, value); }
        }

        /// <summary>
        /// Gets or sets the "redirect_uri" parameter.
        /// </summary>
        public string RedirectUri {
            get { return GetParameter<string>(OpenIdConnectConstants.Parameters.RedirectUri); }
            set { SetParameter(OpenIdConnectConstants.Parameters.RedirectUri, value); }
        }

        /// <summary>
        /// Gets or sets the "refresh_token" parameter.
        /// </summary>
        public string RefreshToken {
            get { return GetParameter<string>(OpenIdConnectConstants.Parameters.RefreshToken); }
            set { SetParameter(OpenIdConnectConstants.Parameters.RefreshToken, value); }
        }

        /// <summary>
        /// Gets or sets the "resource" parameter.
        /// </summary>
        public string Resource {
            get { return GetParameter<string>(OpenIdConnectConstants.Parameters.Resource); }
            set { SetParameter(OpenIdConnectConstants.Parameters.Resource, value); }
        }

        /// <summary>
        /// Gets or sets the "scope" parameter.
        /// </summary>
        public string Scope {
            get { return GetParameter<string>(OpenIdConnectConstants.Parameters.Scope); }
            set { SetParameter(OpenIdConnectConstants.Parameters.Scope, value); }
        }

        /// <summary>
        /// Gets or sets the "state" parameter.
        /// </summary>
        public string State {
            get { return GetParameter<string>(OpenIdConnectConstants.Parameters.State); }
            set { SetParameter(OpenIdConnectConstants.Parameters.State, value); }
        }

        /// <summary>
        /// Gets or sets the "token_type" parameter.
        /// </summary>
        public string TokenType {
            get { return GetParameter<string>(OpenIdConnectConstants.Parameters.TokenType); }
            set { SetParameter(OpenIdConnectConstants.Parameters.TokenType, value); }
        }
    }
}
