/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/AspNet-OpenIdConnect-Server/Owin.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Notifications;

namespace Owin.Security.OpenIdConnect.Server {
    /// <summary>
    /// Provides context information used when receiving an authorization code.
    /// </summary>
    public sealed class ReceiveAuthorizationCodeNotification : BaseNotification<OpenIdConnectServerOptions> {
        /// <summary>
        /// Initializes a new instance of the <see cref="ReceiveAuthorizationCodeNotification"/> class
        /// </summary>
        /// <param name="context"></param>
        /// <param name="options"></param>
        /// <param name="code"></param>
        internal ReceiveAuthorizationCodeNotification(
            IOwinContext context,
            OpenIdConnectServerOptions options,
            string code)
            : base(context, options) {
            AuthorizationCode = code;
        }

        /// <summary>
        /// Gets or sets the authentication ticket.
        /// </summary>
        public AuthenticationTicket AuthenticationTicket { get; set; }

        /// <summary>
        /// Gets the authorization code
        /// used by the client application.
        /// </summary>
        public string AuthorizationCode { get; private set; }

        /// <summary>
        /// Deserialize and unprotect the authentication ticket using
        /// <see cref="OpenIdConnectServerOptions.AuthorizationCodeFormat"/>.
        /// </summary>
        /// <returns>The authentication ticket.</returns>
        public AuthenticationTicket DeserializeTicket() {
            return AuthenticationTicket = DeserializeTicket(AuthorizationCode);
        }

        /// <summary>
        /// Deserialize and unprotect the authentication ticket using
        /// <see cref="OpenIdConnectServerOptions.AuthorizationCodeFormat"/>.
        /// </summary>
        /// <param name="ticket">The serialized ticket.</param>
        /// <returns>The authentication ticket.</returns>
        public AuthenticationTicket DeserializeTicket(string ticket) {
            return AuthenticationTicket = Options.AuthorizationCodeFormat.Unprotect(ticket);
        }
    }
}
