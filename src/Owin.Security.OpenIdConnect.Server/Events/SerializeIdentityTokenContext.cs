/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using AspNet.Security.OpenIdConnect.Primitives;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Owin.Security.OpenIdConnect.Extensions;

namespace Owin.Security.OpenIdConnect.Server
{
    /// <summary>
    /// Represents the context class associated with the
    /// <see cref="OpenIdConnectServerProvider.SerializeIdentityToken"/> event.
    /// </summary>
    public class SerializeIdentityTokenContext : BaseSerializingContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="SerializeIdentityTokenContext"/> class.
        /// </summary>
        public SerializeIdentityTokenContext(
            IOwinContext context,
            OpenIdConnectServerOptions options,
            OpenIdConnectRequest request,
            OpenIdConnectResponse response,
            AuthenticationTicket ticket)
            : base(context, options, request, response, ticket)
        {
        }

        /// <summary>
        /// Gets or sets the issuer address.
        /// </summary>
        public string Issuer { get; set; }

        /// <summary>
        /// Gets or sets the audiences associated with the authentication ticket.
        /// </summary>
        public IEnumerable<string> Audiences
        {
            get => Ticket.GetAudiences();
            set => Ticket.SetAudiences(value);
        }

        /// <summary>
        /// Gets or sets the presenters associated with the authentication ticket.
        /// </summary>
        public IEnumerable<string> Presenters
        {
            get => Ticket.GetPresenters();
            set => Ticket.SetPresenters(value);
        }

        /// <summary>
        /// Gets or sets the encrypting credentials used to encrypt the identity token.
        /// </summary>
        public EncryptingCredentials EncryptingCredentials { get; set; }

        /// <summary>
        /// Gets or sets the signing credentials used to sign the identity token.
        /// </summary>
        public SigningCredentials SigningCredentials { get; set; }

        /// <summary>
        /// Gets or sets the security token handler used to serialize the authentication ticket.
        /// </summary>
        public JwtSecurityTokenHandler SecurityTokenHandler { get; set; }

        /// <summary>
        /// Gets or sets the identity token returned to the client application.
        /// </summary>
        public string IdentityToken { get; set; }
    }
}
