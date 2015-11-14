/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Threading.Tasks;
using Microsoft.AspNet.Authentication;
using Microsoft.AspNet.Http;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace AspNet.Security.OpenIdConnect.Server {
    /// <summary>
    /// Provides context information used when issuing an identity token.
    /// </summary>
    public sealed class SerializeIdentityTokenContext : BaseControlContext {
        /// <summary>
        /// Initializes a new instance of the <see cref="SerializeIdentityTokenContext"/> class
        /// </summary>
        /// <param name="context"></param>
        /// <param name="options"></param>
        /// <param name="request"></param>
        /// <param name="response"></param>
        /// <param name="ticket"></param>
        internal SerializeIdentityTokenContext(
            HttpContext context,
            OpenIdConnectServerOptions options,
            OpenIdConnectMessage request,
            OpenIdConnectMessage response,
            AuthenticationTicket ticket)
            : base(context) {
            Options = options;
            Request = request;
            Response = response;
            AuthenticationTicket = ticket;
        }

        /// <summary>
        /// Gets the options used by the OpenID Connect server.
        /// </summary>
        public OpenIdConnectServerOptions Options { get; }

        /// <summary>
        /// Gets the authorization or token request.
        /// </summary>
        public new OpenIdConnectMessage Request { get; }

        /// <summary>
        /// Gets the authorization or token response.
        /// </summary>
        public new OpenIdConnectMessage Response { get; }

        /// <summary>
        /// Gets or sets the access token hash.
        /// </summary>
        public string AtHash { get; set; }

        /// <summary>
        /// Gets the list of audiences.
        /// </summary>
        public IList<string> Audiences { get; } = new List<string>();

        /// <summary>
        /// Gets or sets the authorization code hash.
        /// </summary>
        public string CHash { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether the token is considered as confidential.
        /// Confidentials tokens can only be validated using the introspection endpoint by fully
        /// authenticated client applications. Updating this property is generally not recommended.
        /// </summary>
        public bool Confidential { get; set; }

        /// <summary>
        /// Gets or sets the issuer address.
        /// </summary>
        public string Issuer { get; set; }

        /// <summary>
        /// Gets or sets the nonce claim.
        /// </summary>
        public string Nonce { get; set; }

        /// <summary>
        /// Gets or sets the unique identifier used as the subject claim.
        /// </summary>
        public string Subject { get; set; }

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
        public Task<string> SerializeTicketAsync() => SerializeTicketAsync(AuthenticationTicket);

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
