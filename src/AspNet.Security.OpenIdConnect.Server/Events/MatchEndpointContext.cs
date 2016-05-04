/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace AspNet.Security.OpenIdConnect.Server {
    /// <summary>
    /// Provides context information used when determining the OpenIdConnect flow type based on the request.
    /// </summary>
    public class MatchEndpointContext : BaseControlContext {
        /// <summary>
        /// Initializes a new instance of the <see cref="MatchEndpointContext"/> class
        /// </summary>
        /// <param name="context"></param>
        /// <param name="options"></param>
        public MatchEndpointContext(
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
        /// Gets whether or not the endpoint is an introspection endpoint.
        /// </summary>
        public bool IsIntrospectionEndpoint { get; private set; }

        /// <summary>
        /// Gets whether or not the endpoint is a logout endpoint.
        /// </summary>
        public bool IsLogoutEndpoint { get; private set; }

        /// <summary>
        /// Gets whether or not the endpoint is a revocation endpoint.
        /// </summary>
        public bool IsRevocationEndpoint { get; private set; }

        /// <summary>
        /// Gets whether or not the endpoint is an
        /// OAuth2/OpenID Connect token endpoint.
        /// </summary>
        public bool IsTokenEndpoint { get; private set; }

        /// <summary>
        /// Gets whether or not the endpoint is an userinfo endpoint.
        /// </summary>
        public bool IsUserinfoEndpoint { get; private set; }

        /// <summary>
        /// Sets the endpoint type to the authorization endpoint.
        /// </summary>
        public void MatchesAuthorizationEndpoint() {
            IsAuthorizationEndpoint = true;
            IsConfigurationEndpoint = false;
            IsCryptographyEndpoint = false;
            IsIntrospectionEndpoint = false;
            IsLogoutEndpoint = false;
            IsRevocationEndpoint = false;
            IsTokenEndpoint = false;
            IsUserinfoEndpoint = false;
        }

        /// <summary>
        /// Sets the endpoint type to the configuration endpoint.
        /// </summary>
        public void MatchesConfigurationEndpoint() {
            IsAuthorizationEndpoint = false;
            IsConfigurationEndpoint = true;
            IsCryptographyEndpoint = false;
            IsIntrospectionEndpoint = false;
            IsLogoutEndpoint = false;
            IsRevocationEndpoint = false;
            IsTokenEndpoint = false;
            IsUserinfoEndpoint = false;
        }

        /// <summary>
        /// Sets the endpoint type to the JWKS endpoint.
        /// </summary>
        public void MatchesCryptographyEndpoint() {
            IsAuthorizationEndpoint = false;
            IsConfigurationEndpoint = false;
            IsCryptographyEndpoint = true;
            IsIntrospectionEndpoint = false;
            IsLogoutEndpoint = false;
            IsRevocationEndpoint = false;
            IsTokenEndpoint = false;
            IsUserinfoEndpoint = false;
        }

        /// <summary>
        /// Sets the endpoint type to introspection endpoint.
        /// </summary>
        public void MatchesIntrospectionEndpoint() {
            IsAuthorizationEndpoint = false;
            IsConfigurationEndpoint = false;
            IsCryptographyEndpoint = false;
            IsIntrospectionEndpoint = true;
            IsLogoutEndpoint = false;
            IsRevocationEndpoint = false;
            IsTokenEndpoint = false;
            IsUserinfoEndpoint = false;
        }

        /// <summary>
        /// Sets the endpoint type to logout endpoint.
        /// </summary>
        public void MatchesLogoutEndpoint() {
            IsAuthorizationEndpoint = false;
            IsConfigurationEndpoint = false;
            IsCryptographyEndpoint = false;
            IsIntrospectionEndpoint = false;
            IsLogoutEndpoint = true;
            IsRevocationEndpoint = false;
            IsTokenEndpoint = false;
            IsUserinfoEndpoint = false;
        }

        /// <summary>
        /// Sets the endpoint type to revocation endpoint.
        /// </summary>
        public void MatchesRevocationEndpoint() {
            IsAuthorizationEndpoint = false;
            IsConfigurationEndpoint = false;
            IsCryptographyEndpoint = false;
            IsIntrospectionEndpoint = false;
            IsLogoutEndpoint = false;
            IsRevocationEndpoint = true;
            IsTokenEndpoint = false;
            IsUserinfoEndpoint = false;
        }

        /// <summary>
        /// Sets the endpoint type to token endpoint.
        /// </summary>
        public void MatchesTokenEndpoint() {
            IsAuthorizationEndpoint = false;
            IsConfigurationEndpoint = false;
            IsCryptographyEndpoint = false;
            IsIntrospectionEndpoint = false;
            IsLogoutEndpoint = false;
            IsRevocationEndpoint = false;
            IsTokenEndpoint = true;
            IsUserinfoEndpoint = false;
        }

        /// <summary>
        /// Sets the endpoint type to userinfo endpoint.
        /// </summary>
        public void MatchesUserinfoEndpoint() {
            IsAuthorizationEndpoint = false;
            IsConfigurationEndpoint = false;
            IsCryptographyEndpoint = false;
            IsIntrospectionEndpoint = false;
            IsLogoutEndpoint = false;
            IsRevocationEndpoint = false;
            IsTokenEndpoint = false;
            IsUserinfoEndpoint = true;
        }

        /// <summary>
        /// Sets the endpoint type to unknown.
        /// </summary>
        public void MatchesNothing() {
            IsAuthorizationEndpoint = false;
            IsConfigurationEndpoint = false;
            IsCryptographyEndpoint = false;
            IsIntrospectionEndpoint = false;
            IsLogoutEndpoint = false;
            IsRevocationEndpoint = false;
            IsTokenEndpoint = false;
            IsUserinfoEndpoint = false;
        }
    }
}
