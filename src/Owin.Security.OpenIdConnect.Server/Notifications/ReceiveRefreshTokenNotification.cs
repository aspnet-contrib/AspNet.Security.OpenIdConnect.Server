/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using Microsoft.IdentityModel.Protocols;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Notifications;

namespace Owin.Security.OpenIdConnect.Server {
    /// <summary>
    /// Provides context information used when receiving a refresh token.
    /// </summary>
    public sealed class ReceiveRefreshTokenNotification : BaseNotification<OpenIdConnectServerOptions> {
        /// <summary>
        /// Initializes a new instance of the <see cref="ReceiveRefreshTokenNotification"/> class
        /// </summary>
        /// <param name="context"></param>
        /// <param name="options"></param>
        /// <param name="request"></param>
        /// <param name="token"></param>
        internal ReceiveRefreshTokenNotification(
            IOwinContext context,
            OpenIdConnectServerOptions options,
            OpenIdConnectMessage request,
            string token)
            : base(context, options) {
            Request = request;
            RefreshToken = token;
        }

        /// <summary>
        /// Gets the authorization or token request.
        /// </summary>
        public new OpenIdConnectMessage Request { get; private set; }

        /// <summary>
        /// Gets or sets the authentication ticket.
        /// </summary>
        public AuthenticationTicket AuthenticationTicket { get; set; }

        /// <summary>
        /// Gets the refresh code used
        /// by the client application.
        /// </summary>
        public string RefreshToken { get; private set; }

        /// <summary>
        /// Deserialize and unprotect the authentication ticket using
        /// <see cref="OpenIdConnectServerOptions.RefreshTokenFormat"/>.
        /// </summary>
        /// <returns>The authentication ticket.</returns>
        public AuthenticationTicket DeserializeTicket() {
            return DeserializeTicket(RefreshToken);
        }

        /// <summary>
        /// Deserialize and unprotect the authentication ticket using
        /// <see cref="OpenIdConnectServerOptions.RefreshTokenFormat"/>.
        /// </summary>
        /// <param name="ticket">The serialized ticket.</param>
        /// <returns>The authentication ticket.</returns>
        public AuthenticationTicket DeserializeTicket(string ticket) {
            return Options.RefreshTokenFormat.Unprotect(ticket);
        }
    }
}
