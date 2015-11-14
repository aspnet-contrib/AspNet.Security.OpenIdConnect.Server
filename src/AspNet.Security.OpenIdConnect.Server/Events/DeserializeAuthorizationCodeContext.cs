/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.ComponentModel;
using System.Threading.Tasks;
using Microsoft.AspNet.Authentication;
using Microsoft.AspNet.Http;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace AspNet.Security.OpenIdConnect.Server {
    /// <summary>
    /// Provides context information used when receiving an authorization code.
    /// </summary>
    public sealed class DeserializeAuthorizationCodeContext : BaseControlContext {
        /// <summary>
        /// Initializes a new instance of the <see cref="DeserializeAuthorizationCodeContext"/> class
        /// </summary>
        /// <param name="context"></param>
        /// <param name="options"></param>
        /// <param name="request"></param>
        /// <param name="code"></param>
        internal DeserializeAuthorizationCodeContext(
            HttpContext context,
            OpenIdConnectServerOptions options,
            OpenIdConnectMessage request,
            string code)
            : base(context) {
            Options = options;
            Request = request;
            AuthorizationCode = code;
        }

        /// <summary>
        /// Gets the options used by the OpenID Connect server.
        /// </summary>
        public OpenIdConnectServerOptions Options { get; }

        /// <summary>
        /// Gets the authorization request.
        /// </summary>
        public new OpenIdConnectMessage Request { get; }

        /// <summary>
        /// Gets or sets the deserializer used to resolve the authentication ticket.
        /// </summary>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public Func<string, Task<AuthenticationTicket>> Deserializer { get; set; }

        /// <summary>
        /// Gets or sets the data format used to deserialize the authentication ticket.
        /// </summary>
        public ISecureDataFormat<AuthenticationTicket> DataFormat { get; set; }

        /// <summary>
        /// Gets the authorization code
        /// used by the client application.
        /// </summary>
        public string AuthorizationCode { get; }

        /// <summary>
        /// Deserialize and verify the authentication ticket.
        /// Note: the <see cref="AuthenticationTicket"/> property
        /// is automatically set when this method completes.
        /// </summary>
        /// <returns>The authentication ticket.</returns>
        public Task<AuthenticationTicket> DeserializeTicketAsync() => DeserializeTicketAsync(AuthorizationCode);

        /// <summary>
        /// Deserialize and verify the authentication ticket.
        /// Note: the <see cref="AuthenticationTicket"/> property
        /// is automatically set when this method completes.
        /// </summary>
        /// <param name="ticket">The serialized ticket.</param>
        /// <returns>The authentication ticket.</returns>
        public async Task<AuthenticationTicket> DeserializeTicketAsync(string ticket) {
            return AuthenticationTicket = await Deserializer(ticket);
        }
    }
}
