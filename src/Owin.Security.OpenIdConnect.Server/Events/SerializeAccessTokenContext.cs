/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System.Collections.Generic;
using System.IdentityModel.Tokens;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Notifications;
using Owin.Security.OpenIdConnect.Extensions;

namespace Owin.Security.OpenIdConnect.Server {
    /// <summary>
    /// Provides context information used when issuing an access token.
    /// </summary>
    public class SerializeAccessTokenContext : BaseNotification<OpenIdConnectServerOptions> {
        /// <summary>
        /// Initializes a new instance of the <see cref="SerializeAccessTokenContext"/> class
        /// </summary>
        /// <param name="context"></param>
        /// <param name="options"></param>
        /// <param name="request"></param>
        /// <param name="response"></param>
        /// <param name="ticket"></param>
        public SerializeAccessTokenContext(
            IOwinContext context,
            OpenIdConnectServerOptions options,
            OpenIdConnectRequest request,
            OpenIdConnectResponse response,
            AuthenticationTicket ticket)
            : base(context, options) {
            Request = request;
            Response = response;
            Ticket = ticket;
        }

        /// <summary>
        /// Gets the authorization or token request.
        /// </summary>
        public new OpenIdConnectRequest Request { get; }

        /// <summary>
        /// Gets the authorization or token response.
        /// </summary>
        public new OpenIdConnectResponse Response { get; }

        /// <summary>
        /// Gets the authentication ticket.
        /// </summary>
        public AuthenticationTicket Ticket { get; }

        /// <summary>
        /// Gets or sets the issuer address.
        /// </summary>
        public string Issuer { get; set; }

        /// <summary>
        /// Gets or sets the audiences associated with the authentication ticket.
        /// </summary>
        public IEnumerable<string> Audiences {
            get { return Ticket.GetAudiences(); }
            set { Ticket.SetAudiences(value); }
        }

        /// <summary>
        /// Gets or sets the presenters associated with the authentication ticket.
        /// </summary>
        public IEnumerable<string> Presenters {
            get { return Ticket.GetPresenters(); }
            set { Ticket.SetPresenters(value); }
        }

        /// <summary>
        /// Gets or sets the scopes associated with the authentication ticket.
        /// </summary>
        public IEnumerable<string> Scopes {
            get { return Ticket.GetScopes(); }
            set { Ticket.SetScopes(value); }
        }

        /// <summary>
        /// Gets or sets the encrypting credentials used to protect the access token.
        /// Both asymmetric and symmetric keys can be used, but choosing a per-client
        /// asymmetric key is strongly recommended. When an asymmetric algorithm is used,
        /// a new symmetric key is dynamically generated and encrypted using the asymmetric key.
        /// </summary>
        public EncryptingCredentials EncryptingCredentials { get; set; }

        /// <summary>
        /// Gets or sets the signing credentials used to sign the access token.
        /// </summary>
        public SigningCredentials SigningCredentials { get; set; }

        /// <summary>
        /// Gets or sets the data format used to serialize the authentication ticket.
        /// Note: this property is only used when <see cref="SecurityTokenHandler"/> is <c>null</c>.
        /// </summary>
        public ISecureDataFormat<AuthenticationTicket> DataFormat { get; set; }

        /// <summary>
        /// Gets or sets the security token handler used to serialize the authentication ticket.
        /// </summary>
        public SecurityTokenHandler SecurityTokenHandler { get; set; }

        /// <summary>
        /// Gets or sets the access token returned to the client application.
        /// </summary>
        public string AccessToken { get; set; }
    }
}
