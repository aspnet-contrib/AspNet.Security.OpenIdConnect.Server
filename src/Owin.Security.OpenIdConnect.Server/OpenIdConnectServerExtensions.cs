/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/AspNet-OpenIdConnect-Server/Owin.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using Owin.Security.OpenIdConnect.Server;

namespace Owin {
    public static class OpenIdConnectServerExtensions {
        /// <summary>
        /// Adds a specs-compliant OpenID connect server in the OWIN pipeline.
        /// </summary>
        /// <param name="app">The web application builder</param>
        /// <param name="options">Options which control the behavior of the OpenID connect server.</param>
        /// <returns>The application builder</returns>
        public static IAppBuilder UseOpenIdConnectServer(this IAppBuilder app, OpenIdConnectServerOptions options) {
            return app.Use(typeof(OpenIdConnectServerMiddleware), app, options);
        }
    }
}
