/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.ComponentModel;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Protocols;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Notifications;

namespace Owin.Security.OpenIdConnect.Server {
    /// <summary>
    /// Provides context information used when issuing a refresh token.
    /// </summary>
    public sealed class CreateRefreshTokenContext : BaseNotification<OpenIdConnectServerOptions> {
        /// <summary>
        /// Initializes a new instance of the <see cref="CreateRefreshTokenContext"/> class
        /// </summary>
        /// <param name="context"></param>
        /// <param name="options"></param>
        /// <param name="request"></param>
        /// <param name="response"></param>
        /// <param name="ticket"></param>
        internal CreateRefreshTokenContext(
            IOwinContext context,
            OpenIdConnectServerOptions options,
            OpenIdConnectMessage request,
            OpenIdConnectMessage response,
            AuthenticationTicket ticket)
            : base(context, options) {
            Request = request;
            Response = response;
            AuthenticationTicket = ticket;
        }

        /// <summary>
        /// Gets the authorization or token request.
        /// </summary>
        public new OpenIdConnectMessage Request { get; }

        /// <summary>
        /// Gets the authorization or token response.
        /// </summary>
        public new OpenIdConnectMessage Response { get; }
        
        /// <summary>
        /// Gets the authentication ticket.
        /// </summary>
        public AuthenticationTicket AuthenticationTicket { get; }

        /// <summary>
        /// Gets or sets the serializer used to forge the refresh token.
        /// </summary>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public Func<AuthenticationTicket, Task<string>> Serializer { get; set; }

        /// <summary>
        /// Gets or sets the data format used to serialize the authentication ticket.
        /// </summary>
        public ISecureDataFormat<AuthenticationTicket> DataFormat { get; set; }

        /// <summary>
        /// Gets or sets the refresh token returned to the client application.
        /// </summary>
        public string RefreshToken { get; set; }

        /// <summary>
        /// Serialize and sign the authentication ticket.
        /// Note: the <see cref="RefreshToken"/> property
        /// is automatically set when this method completes.
        /// </summary>
        /// <returns>The serialized and signed ticket.</returns>
        public async Task<string> SerializeTicketAsync() {
            return RefreshToken = await Serializer(AuthenticationTicket);
        }

        /// <summary>
        /// Serialize and sign the authentication ticket.
        /// Note: the <see cref="RefreshToken"/> property
        /// is automatically set when this method completes.
        /// </summary>
        /// <param name="ticket">The authentication ticket to serialize.</param>
        /// <returns>The serialized and signed ticket.</returns>
        public async Task<string> SerializeTicketAsync(AuthenticationTicket ticket) {
            return RefreshToken = await Serializer(ticket);
        }
    }
}
