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
    /// Provides context information used when receiving an identity token.
    /// </summary>
    public sealed class ReceiveIdentityTokenNotification : BaseNotification<OpenIdConnectServerOptions> {
        /// <summary>
        /// Initializes a new instance of the <see cref="ReceiveAccessTokenNotification"/> class
        /// </summary>
        /// <param name="context"></param>
        /// <param name="options"></param>
        /// <param name="token"></param>
        internal ReceiveIdentityTokenNotification(
            IOwinContext context,
            OpenIdConnectServerOptions options,
            string token)
            : base(context, options) {
            IdentityToken = token;
        }

        /// <summary>
        /// Gets or sets the authentication ticket.
        /// </summary>
        public AuthenticationTicket AuthenticationTicket { get; set; }

        /// <summary>
        /// Gets the identity token used by the client application.
        /// </summary>
        public string IdentityToken { get; private set; }

        /// <summary>
        /// Deserialize and unprotect the authentication ticket using
        /// <see cref="OpenIdConnectServerOptions.AuthorizationCodeFormat"/>.
        /// </summary>
        /// <returns>The authentication ticket.</returns>
        public AuthenticationTicket DeserializeTicket() {
            return DeserializeTicket(IdentityToken);
        }

        /// <summary>
        /// Deserialize and unprotect the authentication ticket using
        /// <see cref="OpenIdConnectServerOptions.AuthorizationCodeFormat"/>.
        /// </summary>
        /// <param name="ticket">The serialized ticket.</param>
        /// <returns>The authentication ticket.</returns>
        public AuthenticationTicket DeserializeTicket(string ticket) {
            return Options.AuthorizationCodeFormat.Unprotect(ticket);
        }
    }
}
