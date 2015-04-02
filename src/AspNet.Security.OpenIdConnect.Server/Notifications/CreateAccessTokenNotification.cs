/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/AspNet-OpenIdConnect-Server/Owin.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using Microsoft.AspNet.Authentication;
using Microsoft.AspNet.Authentication.Notifications;
using Microsoft.AspNet.Http;

namespace AspNet.Security.OpenIdConnect.Server {
    /// <summary>
    /// Provides context information used when issuing an access token.
    /// </summary>
    public sealed class CreateAccessTokenNotification : BaseNotification<OpenIdConnectServerOptions> {
        /// <summary>
        /// Initializes a new instance of the <see cref="CreateAccessTokenNotification"/> class
        /// </summary>
        /// <param name="context"></param>
        /// <param name="options"></param>
        /// <param name="ticket"></param>
        internal CreateAccessTokenNotification(
            HttpContext context,
            OpenIdConnectServerOptions options,
            AuthenticationTicket ticket)
            : base(context, options) {
            AuthenticationTicket = ticket;
        }

        /// <summary>
        /// Gets or sets the access token
        /// returned to the client application.
        /// </summary>
        public string AccessToken { get; set; }

        /// <summary>
        /// Serialize and protect the authentication ticket using
        /// <see cref="OpenIdConnectServerOptions.AccessTokenFormat"/>.
        /// </summary>
        /// <returns>The serialized and protected ticket.</returns>
        public string SerializeTicket() => Options.AccessTokenFormat.Protect(AuthenticationTicket);
    }
}
