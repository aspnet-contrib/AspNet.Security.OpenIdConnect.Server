/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace AspNet.Security.OpenIdConnect.Server
{
    /// <summary>
    /// Represents the context class associated with the
    /// <see cref="OpenIdConnectServerProvider.MatchEndpoint"/> event.
    /// </summary>
    public class MatchEndpointContext : HandleRequestContext<OpenIdConnectServerOptions>
    {
        /// <summary>
        /// Creates a new instance of the <see cref="MatchEndpointContext"/> class.
        /// </summary>
        public MatchEndpointContext(
            HttpContext context,
            AuthenticationScheme scheme,
            OpenIdConnectServerOptions options)
            : base(context, scheme, options)
        {
        }

        /// <summary>
        /// Gets a boolean indicating whether the request
        /// should be handled by the authorization endpoint.
        /// </summary>
        public bool IsAuthorizationEndpoint { get; private set; }

        /// <summary>
        /// Gets a boolean indicating whether the request
        /// should be handled by the configuration endpoint.
        /// </summary>
        public bool IsConfigurationEndpoint { get; private set; }

        /// <summary>
        /// Gets a boolean indicating whether the request
        /// should be handled by the cryptography endpoint.
        /// </summary>
        public bool IsCryptographyEndpoint { get; private set; }

        /// <summary>
        /// Gets a boolean indicating whether the request
        /// should be handled by the introspection endpoint.
        /// </summary>
        public bool IsIntrospectionEndpoint { get; private set; }

        /// <summary>
        /// Gets a boolean indicating whether the request
        /// should be handled by the logout endpoint.
        /// </summary>
        public bool IsLogoutEndpoint { get; private set; }

        /// <summary>
        /// Gets a boolean indicating whether the request
        /// should be handled by the revocation endpoint.
        /// </summary>
        public bool IsRevocationEndpoint { get; private set; }

        /// <summary>
        /// Gets a boolean indicating whether the request
        /// should be handled by the token endpoint.
        /// </summary>
        public bool IsTokenEndpoint { get; private set; }

        /// <summary>
        /// Gets a boolean indicating whether the request
        /// should be handled by the userinfo endpoint.
        /// </summary>
        public bool IsUserinfoEndpoint { get; private set; }

        /// <summary>
        /// Indicates that the request should be
        /// handled by the authorization endpoint.
        /// </summary>
        public void MatchAuthorizationEndpoint()
        {
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
        /// Indicates that the request should be
        /// handled by the configuration endpoint.
        /// </summary>
        public void MatchConfigurationEndpoint()
        {
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
        /// Indicates that the request should be
        /// handled by the cryptography endpoint.
        /// </summary>
        public void MatchCryptographyEndpoint()
        {
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
        /// Indicates that the request should be
        /// handled by the introspection endpoint.
        /// </summary>
        public void MatchIntrospectionEndpoint()
        {
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
        /// Indicates that the request should be
        /// handled by the logout endpoint.
        /// </summary>
        public void MatchLogoutEndpoint()
        {
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
        /// Indicates that the request should be
        /// handled by the revocation endpoint.
        /// </summary>
        public void MatchRevocationEndpoint()
        {
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
        /// Indicates that the request should be
        /// handled by the token endpoint.
        /// </summary>
        public void MatchTokenEndpoint()
        {
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
        /// Indicates that the request should be
        /// handled by the userinfo endpoint.
        /// </summary>
        public void MatchUserinfoEndpoint()
        {
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
        /// Indicates that the request shouldn't be handled
        /// by the OpenID Connect server middleware.
        /// </summary>
        public void MatchNothing()
        {
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
