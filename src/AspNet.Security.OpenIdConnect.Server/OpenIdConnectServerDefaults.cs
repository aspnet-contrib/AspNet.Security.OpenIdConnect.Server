/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using Microsoft.AspNet.Authentication;

namespace AspNet.Security.OpenIdConnect.Server {
    /// <summary>
    /// Default values used by authorization server.
    /// </summary>
    public static class OpenIdConnectServerDefaults {
        /// <summary>
        /// Default value for <see cref="AuthenticationOptions.AuthenticationScheme"/>.
        /// </summary>
        public const string AuthenticationScheme = "oidc-server";

        /// <summary>
        /// Default value for <see cref="OpenIdConnectServerOptions.AuthorizationEndpointPath"/>.
        /// </summary>
        public const string AuthorizationEndpointPath = "/connect/authorize";

        /// <summary>
        /// Default value for <see cref="OpenIdConnectServerOptions.ConfigurationEndpointPath"/>.
        /// </summary>
        public const string ConfigurationEndpointPath = "/.well-known/openid-configuration";

        /// <summary>
        /// Default value for <see cref="OpenIdConnectServerOptions.CryptographyEndpointPath"/>.
        /// </summary>
        public const string CryptographyEndpointPath = "/.well-known/jwks";

        /// <summary>
        /// Default value for <see cref="OpenIdConnectServerOptions.TokenEndpointPath"/>.
        /// </summary>
        public const string TokenEndpointPath = "/connect/token";

        /// <summary>
        /// Default value for <see cref="OpenIdConnectServerOptions.ProfileEndpointPath"/>.
        /// </summary>
        public const string ProfileEndpointPath = "/connect/userinfo";

        /// <summary>
        /// Default value for <see cref="OpenIdConnectServerOptions.ValidationEndpointPath"/>.
        /// </summary>
        public const string ValidationEndpointPath = "/connect/introspect";

        /// <summary>
        /// Default value for <see cref="OpenIdConnectServerOptions.LogoutEndpointPath"/>.
        /// </summary>
        public const string LogoutEndpointPath = "/connect/logout";
    }
}
