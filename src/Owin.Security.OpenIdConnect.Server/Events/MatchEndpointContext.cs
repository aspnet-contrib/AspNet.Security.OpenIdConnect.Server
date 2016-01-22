/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using Microsoft.Owin;
using Microsoft.Owin.Security.Notifications;

namespace Owin.Security.OpenIdConnect.Server {
    /// <summary>
    /// Provides context information used when determining the OpenIdConnect flow type based on the request.
    /// </summary>
    public sealed class MatchEndpointContext : BaseNotification<OpenIdConnectServerOptions> {
        /// <summary>
        /// Initializes a new instance of the <see cref="MatchEndpointContext"/> class
        /// </summary>
        /// <param name="context"></param>
        /// <param name="options"></param>
        internal MatchEndpointContext(
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
        public bool IsCryptographyEndpoint { get; private set; }

        /// <summary>
        /// Gets whether or not the endpoint is an
        /// OAuth2/OpenID Connect token endpoint.
        /// </summary>
        public bool IsTokenEndpoint { get; private set; }

        /// <summary>
        /// Gets whether or not the endpoint is an userinfo endpoint.
        /// </summary>
        public bool IsProfileEndpoint { get; private set; }

        /// <summary>
        /// Gets whether or not the endpoint is an introspection endpoint.
        /// </summary>
        public bool IsIntrospectionEndpoint { get; private set; }

        /// <summary>
        /// Gets whether or not the endpoint is a logout endpoint.
        /// </summary>
        public bool IsLogoutEndpoint { get; private set; }

        /// <summary>
        /// Sets the endpoint type to the authorization endpoint.
        /// </summary>
        public void MatchesAuthorizationEndpoint() {
            IsAuthorizationEndpoint = true;
            IsConfigurationEndpoint = false;
            IsCryptographyEndpoint = false;
            IsTokenEndpoint = false;
            IsProfileEndpoint = false;
            IsIntrospectionEndpoint = false;
            IsLogoutEndpoint = false;
        }

        /// <summary>
        /// Sets the endpoint type to the configuration endpoint.
        /// </summary>
        public void MatchesConfigurationEndpoint() {
            IsAuthorizationEndpoint = false;
            IsConfigurationEndpoint = true;
            IsCryptographyEndpoint = false;
            IsTokenEndpoint = false;
            IsProfileEndpoint = false;
            IsIntrospectionEndpoint = false;
            IsLogoutEndpoint = false;
        }

        /// <summary>
        /// Sets the endpoint type to the JWKS endpoint.
        /// </summary>
        public void MatchesCryptographyEndpoint() {
            IsAuthorizationEndpoint = false;
            IsConfigurationEndpoint = false;
            IsCryptographyEndpoint = true;
            IsTokenEndpoint = false;
            IsProfileEndpoint = false;
            IsIntrospectionEndpoint = false;
            IsLogoutEndpoint = false;
        }

        /// <summary>
        /// Sets the endpoint type to token endpoint.
        /// </summary>
        public void MatchesTokenEndpoint() {
            IsAuthorizationEndpoint = false;
            IsConfigurationEndpoint = false;
            IsCryptographyEndpoint = false;
            IsTokenEndpoint = true;
            IsProfileEndpoint = false;
            IsIntrospectionEndpoint = false;
            IsLogoutEndpoint = false;
        }

        /// <summary>
        /// Sets the endpoint type to userinfo endpoint.
        /// </summary>
        public void MatchesProfileEndpoint() {
            IsAuthorizationEndpoint = false;
            IsConfigurationEndpoint = false;
            IsCryptographyEndpoint = false;
            IsTokenEndpoint = false;
            IsProfileEndpoint = true;
            IsIntrospectionEndpoint = false;
            IsLogoutEndpoint = false;
        }

        /// <summary>
        /// Sets the endpoint type to introspection endpoint.
        /// </summary>
        public void MatchesIntrospectionEndpoint() {
            IsAuthorizationEndpoint = false;
            IsConfigurationEndpoint = false;
            IsCryptographyEndpoint = false;
            IsTokenEndpoint = false;
            IsProfileEndpoint = false;
            IsIntrospectionEndpoint = true;
            IsLogoutEndpoint = false;
        }

        /// <summary>
        /// Sets the endpoint type to logout endpoint.
        /// </summary>
        public void MatchesLogoutEndpoint() {
            IsAuthorizationEndpoint = false;
            IsConfigurationEndpoint = false;
            IsCryptographyEndpoint = false;
            IsTokenEndpoint = false;
            IsProfileEndpoint = false;
            IsIntrospectionEndpoint = false;
            IsLogoutEndpoint = true;
        }

        /// <summary>
        /// Sets the endpoint type to unknown.
        /// </summary>
        public void MatchesNothing() {
            IsAuthorizationEndpoint = false;
            IsConfigurationEndpoint = false;
            IsCryptographyEndpoint = false;
            IsTokenEndpoint = false;
            IsProfileEndpoint = false;
            IsIntrospectionEndpoint = false;
            IsLogoutEndpoint = false;
        }
    }
}
