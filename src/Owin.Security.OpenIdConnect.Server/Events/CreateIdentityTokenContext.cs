/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IdentityModel.Tokens;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Protocols;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Notifications;

namespace Owin.Security.OpenIdConnect.Server {
    /// <summary>
    /// Provides context information used when issuing an identity token.
    /// </summary>
    public sealed class CreateIdentityTokenContext : BaseNotification<OpenIdConnectServerOptions> {
        /// <summary>
        /// Initializes a new instance of the <see cref="CreateIdentityTokenContext"/> class
        /// </summary>
        /// <param name="context"></param>
        /// <param name="options"></param>
        /// <param name="request"></param>
        /// <param name="response"></param>
        /// <param name="ticket"></param>
        internal CreateIdentityTokenContext(
            IOwinContext context,
            OpenIdConnectServerOptions options,
            OpenIdConnectMessage request,
            OpenIdConnectMessage response,
            AuthenticationTicket ticket)
            : base(context, options) {
            Request = request;
            Response = response;
            AuthenticationTicket = ticket;
            Audiences = new List<string>();
        }

        /// <summary>
        /// Gets the authorization or token request.
        /// </summary>
        public new OpenIdConnectMessage Request { get; private set; }

        /// <summary>
        /// Gets the authorization or token response.
        /// </summary>
        public new OpenIdConnectMessage Response { get; private set; }

        /// <summary>
        /// Gets the authentication ticket.
        /// </summary>
        public AuthenticationTicket AuthenticationTicket { get; private set; }

        /// <summary>
        /// Gets the list of audiences.
        /// </summary>
        public IList<string> Audiences { get; private set; }

        /// <summary>
        /// Gets or sets the issuer address.
        /// </summary>
        public string Issuer { get; set; }

        /// <summary>
        /// Gets or sets the signature provider used to sign the identity token.
        /// </summary>
        public SignatureProvider SignatureProvider { get; set; }

        /// <summary>
        /// Gets or sets the signing credentials used to sign the identity token.
        /// </summary>
        public SigningCredentials SigningCredentials { get; set; }

        /// <summary>
        /// Gets or sets the serializer used to forge the identity token.
        /// </summary>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public Func<AuthenticationTicket, Task<string>> Serializer { get; set; }

        /// <summary>
        /// Gets or sets the security token handler used to serialize the authentication ticket.
        /// </summary>
        public JwtSecurityTokenHandler SecurityTokenHandler { get; set; }

        /// <summary>
        /// Gets or sets the identity token returned to the client application.
        /// </summary>
        public string IdentityToken { get; set; }

        /// <summary>
        /// Serialize and sign the authentication ticket.
        /// Note: the <see cref="IdentityToken"/> property
        /// is automatically set when this method completes.
        /// </summary>
        /// <returns>The serialized and signed ticket.</returns>
        public async Task<string> SerializeTicketAsync() {
            return IdentityToken = await Serializer(AuthenticationTicket);
        }

        /// <summary>
        /// Serialize and sign the authentication ticket.
        /// Note: the <see cref="IdentityToken"/> property
        /// is automatically set when this method completes.
        /// </summary>
        /// <param name="ticket">The authentication ticket to serialize.</param>
        /// <returns>The serialized and signed ticket.</returns>
        public async Task<string> SerializeTicketAsync(AuthenticationTicket ticket) {
            return IdentityToken = await Serializer(ticket);
        }
    }
}
