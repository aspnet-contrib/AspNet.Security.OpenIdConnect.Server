/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/AspNet-OpenIdConnect-Server/Owin.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using Microsoft.Owin;
using Microsoft.Owin.Security.Provider;

namespace Owin.Security.OpenIdConnect.Server {
    /// <summary>
    /// An event raised before the authorization server starts
    /// writing the configuration metadata to the response stream.
    /// </summary>
    public class OpenIdConnectConfigurationEndpointResponseContext : EndpointContext<OpenIdConnectServerOptions> {
        /// <summary>
        /// Creates an instance of this context.
        /// </summary>
        public OpenIdConnectConfigurationEndpointResponseContext(
            IOwinContext context,
            OpenIdConnectServerOptions options)
            : base(context, options) {
            AdditionalParameters = new Dictionary<string, object>(StringComparer.Ordinal);
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
        public IDictionary<string, object> AdditionalParameters { get; private set; }

        /// <summary>
        /// Gets or sets the crypto endpoint address.
        /// </summary>
        public string CryptoEndpoint { get; set; }

        /// <summary>
        /// Gets or sets the issuer address.
        /// </summary>
        public string Issuer { get; set; }

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
