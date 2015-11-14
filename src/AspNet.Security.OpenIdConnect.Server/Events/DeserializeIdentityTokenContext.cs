/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.ComponentModel;
using System.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNet.Authentication;
using Microsoft.AspNet.Http;
using Microsoft.AspNet.Http.Authentication;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace AspNet.Security.OpenIdConnect.Server {
    /// <summary>
    /// Provides context information used when receiving an identity token.
    /// </summary>
    public sealed class DeserializeIdentityTokenContext : BaseControlContext {
        /// <summary>
        /// Initializes a new instance of the <see cref="DeserializeIdentityTokenContext"/> class
        /// </summary>
        /// <param name="context"></param>
        /// <param name="options"></param>
        /// <param name="request"></param>
        /// <param name="token"></param>
        internal DeserializeIdentityTokenContext(
            HttpContext context,
            OpenIdConnectServerOptions options,
            OpenIdConnectMessage request,
            string token)
            : base(context) {
            Options = options;
            Request = request;
            IdentityToken = token;
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
        /// Gets or sets the issuer address.
        /// </summary>
        public string Issuer { get; set; }

        /// <summary>
        /// Gets or sets the signature provider used to
        /// verify the authenticity of the identity token.
        /// </summary>
        public SignatureProvider SignatureProvider { get; set; }

        /// <summary>
        /// Gets or sets the signing key used to
        /// verify the authenticity of the identity token.
        /// </summary>
        public SecurityKey SigningKey { get; set; }

        /// <summary>
        /// Gets or sets the deserializer used to resolve the authentication ticket.
        /// </summary>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public Func<string, Task<AuthenticationTicket>> Deserializer { get; set; }

        /// <summary>
        /// Gets or sets the security token handler used to
        /// deserialize the authentication ticket.
        /// </summary>
        public JwtSecurityTokenHandler SecurityTokenHandler { get; set; }

        /// <summary>
        /// Gets the identity token used by the client application.
        /// </summary>
        public string IdentityToken { get; }

        /// <summary>
        /// Deserialize and unprotect the authentication ticket.
        /// Note: the <see cref="AuthenticationTicket"/> property
        /// is automatically set when this method completes.
        /// </summary>
        /// <returns>The authentication ticket.</returns>
        public Task<AuthenticationTicket> DeserializeTicketAsync() => DeserializeTicketAsync(IdentityToken);

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
