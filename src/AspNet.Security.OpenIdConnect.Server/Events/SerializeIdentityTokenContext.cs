/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using AspNet.Security.OpenIdConnect.Extensions;
using Microsoft.AspNet.Authentication;
using Microsoft.AspNet.Http;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace AspNet.Security.OpenIdConnect.Server {
    /// <summary>
    /// Provides context information used when issuing an identity token.
    /// </summary>
    public sealed class SerializeIdentityTokenContext : BaseContext {
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
        /// Gets the authentication ticket to serialize.
        /// </summary>
        public AuthenticationTicket AuthenticationTicket { get; }

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
        /// Gets or sets the issuer address.
        /// </summary>
        public string Issuer { get; set; }

        /// <summary>
        /// Gets or sets the audiences associated with the authentication ticket.
        /// </summary>
        public IEnumerable<string> Audiences {
            get { return AuthenticationTicket.GetAudiences(); }
            set { AuthenticationTicket.SetAudiences(value); }
        }

        /// <summary>
        /// Gets or sets the presenters associated with the authentication ticket.
        /// </summary>
        public IEnumerable<string> Presenters {
            get { return AuthenticationTicket.GetPresenters(); }
            set { AuthenticationTicket.SetPresenters(value); }
        }

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
