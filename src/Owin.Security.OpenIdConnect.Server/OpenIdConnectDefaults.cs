/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/AspNet-OpenIdConnect-Server/Owin.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

namespace Owin.Security.OpenIdConnect.Server {
    /// <summary>
    /// Default values used by authorization server and bearer authentication.
    /// </summary>
    public static class OpenIdConnectDefaults {
        /// <summary>
        /// Default value for AuthenticationType property in the OpenIdConnectBearerAuthenticationOptions and
        /// OpenIdConnectServerOptions.
        /// </summary>
        public const string AuthenticationType = "Bearer";

        /// <summary>
        /// Default value for OpenIdConnectServerOptions.AuthorizationEndpointPath.
        /// </summary>
        public const string AuthorizationEndpointPath = "/connect/authorize";

        /// <summary>
        /// Default value for OpenIdConnectServerOptions.ConfigurationEndpointPath.
        /// </summary>
        public const string ConfigurationEndpointPath = "/.well-known/openid-configuration";

        /// <summary>
        /// Default value for OpenIdConnectServerOptions.CryptoEndpointPath.
        /// </summary>
        public const string CryptoEndpointPath = "/.well-known/jwks";

        /// <summary>
        /// Default value for OpenIdConnectServerOptions.TokenEndpointPath.
        /// </summary>
        public const string TokenEndpointPath = "/connect/token";
    }
}
