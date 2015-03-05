/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/AspNet-OpenIdConnect-Server/Owin.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using Microsoft.AspNet.Authentication.Notifications;
using Microsoft.AspNet.Http;
using Newtonsoft.Json.Linq;

namespace AspNet.Security.OpenIdConnect.Server {
    /// <summary>
    /// An event raised before the authorization server starts
    /// writing the configuration metadata to the response stream.
    /// </summary>
    public sealed class OpenIdConnectConfigurationEndpointResponseContext : EndpointContext<OpenIdConnectServerOptions> {
        /// <summary>
        /// Creates an instance of this context.
        /// </summary>
        internal OpenIdConnectConfigurationEndpointResponseContext(
            HttpContext context,
            OpenIdConnectServerOptions options)
            : base(context, options) {
            AdditionalParameters = new Dictionary<string, JToken>(StringComparer.Ordinal);
            GrantTypes = new List<string>();
            ResponseModes = new List<string>();
            ResponseTypes = new List<string>();
            Scopes = new List<string>();
            SigningAlgorithms = new List<string>();
            SubjectTypes = new List<string>();
        }

        /// <summary>
        /// Gets or sets the authorization endpoint address.
        /// </summary>
        public string AuthorizationEndpoint { get; set; }

        /// <summary>
        /// Enables additional values to be appended to the metadata response.
        /// </summary>
        public IDictionary<string, JToken> AdditionalParameters { get; private set; }

        /// <summary>
        /// Gets or sets the JWKS endpoint address.
        /// </summary>
        public string KeyEndpoint { get; set; }

        /// <summary>
        /// Gets or sets the issuer address.
        /// </summary>
        public string Issuer { get; set; }

        /// <summary>
        /// Gets a list of the grant types
        /// supported by the authorization server.
        /// </summary>
        public IList<string> GrantTypes { get; private set; }

        /// <summary>
        /// Gets a list of the response modes
        /// supported by the authorization server.
        /// </summary>
        public IList<string> ResponseModes { get; private set; }

        /// <summary>
        /// Gets a list of the response types
        /// supported by the authorization server.
        /// </summary>
        public IList<string> ResponseTypes { get; private set; }

        /// <summary>
        /// Gets a list of the scope values
        /// supported by the authorization server.
        /// </summary>
        public IList<string> Scopes { get; private set; }

        /// <summary>
        /// Gets a list of the signing algorithms
        /// supported by the authorization server.
        /// </summary>
        public IList<string> SigningAlgorithms { get; private set; }

        /// <summary>
        /// Gets a list of the subject types
        /// supported by the authorization server.
        /// </summary>
        public IList<string> SubjectTypes { get; private set; }

        /// <summary>
        /// Gets or sets the token endpoint address.
        /// </summary>
        public string TokenEndpoint { get; set; }
    }
}
