/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using Microsoft.IdentityModel.Protocols;
using Microsoft.Owin;
using Microsoft.Owin.Security.Notifications;

namespace Owin.Security.OpenIdConnect.Server {
    /// <summary>
    /// Provides context information when processing a logout response.
    /// </summary>
    public sealed class LogoutEndpointResponseNotification : BaseNotification<OpenIdConnectServerOptions> {
        /// <summary>
        /// Initializes a new instance of the <see cref="LogoutEndpointResponseNotification"/> class
        /// </summary>
        /// <param name="context"></param>
        /// <param name="options"></param>
        /// <param name="request"></param>
        internal LogoutEndpointResponseNotification(
            IOwinContext context,
            OpenIdConnectServerOptions options,
            OpenIdConnectMessage request)
            : base(context, options) {
            Request = request;
        }

        /// <summary>
        /// Gets the authorization request. 
        /// </summary>
        public new OpenIdConnectMessage Request { get; private set; }
    }
}
