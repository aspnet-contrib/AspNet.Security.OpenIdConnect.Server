/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/AspNet-OpenIdConnect-Server/Owin.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using Microsoft.AspNet.Security;

namespace AspNet.Security.OpenIdConnect.Server {
    /// <summary>
    /// Default values used by authorization server and bearer authentication.
    /// </summary>
    public static class OpenIdConnectDefaults {
        /// <summary>
        /// Default value for <see cref="AuthenticationOptions.AuthenticationType"/>.
        /// </summary>
        public const string AuthenticationType = "Bearer";

        /// <summary>
        /// Default value for <see cref="OpenIdConnectServerOptions.AuthorizationEndpointPath"/>.
        /// </summary>
        public const string AuthorizationEndpointPath = "/connect/authorize";

        /// <summary>
        /// Default value for <see cref="OpenIdConnectServerOptions.ConfigurationEndpointPath"/>.
        /// </summary>
        public const string ConfigurationEndpointPath = "/.well-known/openid-configuration";

        /// <summary>
        /// Default value for <see cref="OpenIdConnectServerOptions.KeysEndpointPath"/>.
        /// </summary>
        public const string KeysEndpointPath = "/.well-known/jwks";

        /// <summary>
        /// Default value for <see cref="OpenIdConnectServerOptions.TokenEndpointPath"/>.
        /// </summary>
        public const string TokenEndpointPath = "/connect/token";
    }
}
