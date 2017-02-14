/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using Microsoft.Owin.Security;

namespace Owin.Security.OpenIdConnect.Server
{
    /// <summary>
    /// Exposes the default values used by the OpenID Connect server middleware.
    /// </summary>
    public static class OpenIdConnectServerDefaults
    {
        /// <summary>
        /// Default value for <see cref="AuthenticationOptions.AuthenticationType"/>.
        /// </summary>
        public const string AuthenticationType = "ASOS";
    }
}
