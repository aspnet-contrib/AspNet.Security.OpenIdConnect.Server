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
    /// Provides context information used when issuing a refresh token.
    /// </summary>
    public sealed class CreateRefreshTokenNotification : BaseNotification<OpenIdConnectServerOptions> {
        /// <summary>
        /// Initializes a new instance of the <see cref="CreateRefreshTokenNotification"/> class
        /// </summary>
        /// <param name="context"></param>
        /// <param name="options"></param>
        /// <param name="request"></param>
        /// <param name="response"></param>
        /// <param name="ticket"></param>
        internal CreateRefreshTokenNotification(
            IOwinContext context,
            OpenIdConnectServerOptions options,
            OpenIdConnectMessage request,
            OpenIdConnectMessage response,
            AuthenticationTicket ticket)
            : base(context, options) {
            TokenRequest = request;
            TokenResponse = response;
            AuthenticationTicket = ticket;
        }

        /// <summary>
        /// Gets the authorization or token request.
        /// </summary>
        public OpenIdConnectMessage TokenRequest { get; private set; }

        /// <summary>
        /// Gets the authorization or token response.
        /// </summary>
        public OpenIdConnectMessage TokenResponse { get; private set; }
        
        /// <summary>
        /// Gets the authentication ticket.
        /// </summary>
        public AuthenticationTicket AuthenticationTicket { get; private set; }

        /// <summary>
        /// Gets or sets the refresh token
        /// returned to the client application.
        /// </summary>
        public string RefreshToken { get; set; }

        /// <summary>
        /// Serialize and protect the authentication ticket using
        /// <see cref="OpenIdConnectServerOptions.RefreshTokenFormat"/>.
        /// </summary>
        /// <returns>The serialized and protected ticket.</returns>
        public string SerializeTicket() {
            return Options.RefreshTokenFormat.Protect(AuthenticationTicket);
        }
    }
}
