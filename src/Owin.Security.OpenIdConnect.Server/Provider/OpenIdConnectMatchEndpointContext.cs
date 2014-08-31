/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/AspNet-OpenIdConnect-Server/Owin.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using Microsoft.Owin;
using Microsoft.Owin.Security.Provider;

namespace Owin.Security.OpenIdConnect.Server {
    /// <summary>
    /// Provides context information used when determining the OpenIdConnect flow type based on the request.
    /// </summary>
    public sealed class OpenIdConnectMatchEndpointContext : EndpointContext<OpenIdConnectServerOptions> {
        /// <summary>
        /// Initializes a new instance of the <see cref="OpenIdConnectMatchEndpointContext"/> class
        /// </summary>
        /// <param name="context"></param>
        /// <param name="options"></param>
        internal OpenIdConnectMatchEndpointContext(
            IOwinContext context,
            OpenIdConnectServerOptions options)
            : base(context, options) {
        }

        /// <summary>
        /// Gets whether or not the endpoint is an
        /// OAuth2/OpenID Connect authorization endpoint.
        /// </summary>
        public bool IsAuthorizationEndpoint { get; private set; }

        /// <summary>
        /// Gets whether or not the endpoint is an
        /// OpenID Connect configuration metadata endpoint.
        /// </summary>
        public bool IsConfigurationEndpoint { get; private set; }

        /// <summary>
        /// Gets whether or not the endpoint is an
        /// OpenID Connect JWKS endpoint.
        /// </summary>
        public bool IsKeysEndpoint { get; private set; }

        /// <summary>
        /// Gets whether or not the endpoint is an
        /// OAuth2/OpenID Connect token endpoint.
        /// </summary>
        public bool IsTokenEndpoint { get; private set; }

        /// <summary>
        /// Sets the endpoint type to the authorization endpoint.
        /// </summary>
        public void MatchesAuthorizationEndpoint() {
            IsAuthorizationEndpoint = true;
            IsConfigurationEndpoint = false;
            IsKeysEndpoint = false;
            IsTokenEndpoint = false;
        }

        /// <summary>
        /// Sets the endpoint type to the configuration endpoint.
        /// </summary>
        public void MatchesConfigurationEndpoint() {
            IsAuthorizationEndpoint = false;
            IsConfigurationEndpoint = true;
            IsKeysEndpoint = false;
            IsTokenEndpoint = false;
        }

        /// <summary>
        /// Sets the endpoint type to the JWKS endpoint.
        /// </summary>
        public void MatchesKeysEndpoint() {
            IsAuthorizationEndpoint = false;
            IsConfigurationEndpoint = false;
            IsKeysEndpoint = true;
            IsTokenEndpoint = false;
        }

        /// <summary>
        /// Sets the endpoint type to token endpoint.
        /// </summary>
        public void MatchesTokenEndpoint() {
            IsAuthorizationEndpoint = false;
            IsConfigurationEndpoint = false;
            IsKeysEndpoint = false;
            IsTokenEndpoint = true;
        }

        /// <summary>
        /// Sets the endpoint type to unknown.
        /// </summary>
        public void MatchesNothing() {
            IsAuthorizationEndpoint = false;
            IsConfigurationEndpoint = false;
            IsKeysEndpoint = false;
            IsTokenEndpoint = false;
        }
    }
}
