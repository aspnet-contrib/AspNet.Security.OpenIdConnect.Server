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
    /// Provides context information used when extracting an authorization request.
    /// </summary>
    public sealed class ExtractAuthorizationRequestNotification : BaseNotification<OpenIdConnectServerOptions> {
        /// <summary>
        /// Initializes a new instance of the <see cref="ExtractAuthorizationRequestNotification"/> class
        /// </summary>
        /// <param name="context"></param>
        /// <param name="options"></param>
        internal ExtractAuthorizationRequestNotification(
            IOwinContext context,
            OpenIdConnectServerOptions options)
            : base(context, options) {
        }

        /// <summary>
        /// Gets or sets the authorization request.
        /// </summary>
        public OpenIdConnectMessage AuthorizationRequest { get; set; }
    }
}
