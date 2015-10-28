/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System.Collections.Generic;
using Microsoft.AspNet.Authentication;
using Microsoft.AspNet.Http;

namespace AspNet.Security.OpenIdConnect.Server {
    /// <summary>
    /// An event raised before the authorization server handles
    /// the request made to the configuration metadata endpoint.
    /// </summary>
    public sealed class ConfigurationEndpointContext : BaseControlContext {
        /// <summary>
        /// Creates an instance of this context.
        /// </summary>
        internal ConfigurationEndpointContext(
            HttpContext context,
            OpenIdConnectServerOptions options)
            : base(context) {
            Options = options;
        }

        /// <summary>
        /// Gets the options used by the OpenID Connect server.
        /// </summary>
        public OpenIdConnectServerOptions Options { get; }

        /// <summary>
        /// Gets or sets the authorization endpoint address.
        /// </summary>
        public string AuthorizationEndpoint { get; set; }

        /// <summary>
        /// Gets or sets the JWKS endpoint address.
        /// </summary>
        public string CryptographyEndpoint { get; set; }

        /// <summary>
        /// Gets or sets the userinfo endpoint address.
        /// </summary>
        public string ProfileEndpoint { get; set; }

        /// <summary>
        /// Gets or sets the validation endpoint address.
        /// </summary>
        public string ValidationEndpoint { get; set; }

        /// <summary>
        /// Gets or sets the token endpoint address.
        /// </summary>
        public string TokenEndpoint { get; set; }

        /// <summary>
        /// Gets or sets the logout endpoint address.
        /// </summary>
        public string LogoutEndpoint { get; set; }

        /// <summary>
        /// Gets or sets the issuer address.
        /// </summary>
        public string Issuer { get; set; }

        /// <summary>
        /// Gets a list of the grant types
        /// supported by the authorization server.
        /// </summary>
        public IList<string> GrantTypes { get; } = new List<string>();

        /// <summary>
        /// Gets a list of the response modes
        /// supported by the authorization server.
        /// </summary>
        public IList<string> ResponseModes { get; } = new List<string>();

        /// <summary>
        /// Gets a list of the response types
        /// supported by the authorization server.
        /// </summary>
        public IList<string> ResponseTypes { get; } = new List<string>();

        /// <summary>
        /// Gets a list of the scope values
        /// supported by the authorization server.
        /// </summary>
        public IList<string> Scopes { get; } = new List<string>();

        /// <summary>
        /// Gets a list of the signing algorithms
        /// supported by the authorization server.
        /// </summary>
        public IList<string> SigningAlgorithms { get; } = new List<string>();

        /// <summary>
        /// Gets a list of the subject types
        /// supported by the authorization server.
        /// </summary>
        public IList<string> SubjectTypes { get; } = new List<string>();
    }
}
