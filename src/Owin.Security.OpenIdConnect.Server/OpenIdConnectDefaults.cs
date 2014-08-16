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
    }
}
