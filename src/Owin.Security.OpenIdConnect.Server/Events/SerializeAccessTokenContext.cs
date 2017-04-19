/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System.Collections.Generic;
using System.IdentityModel.Tokens;
using AspNet.Security.OpenIdConnect.Primitives;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Notifications;
using Owin.Security.OpenIdConnect.Extensions;

namespace Owin.Security.OpenIdConnect.Server
{
    /// <summary>
    /// Represents the context class associated with the
    /// <see cref="OpenIdConnectServerProvider.SerializeAccessToken"/> event.
    /// </summary>
    public class SerializeAccessTokenContext : BaseNotification<OpenIdConnectServerOptions>
    {
        /// <summary>
        /// Creates a new instance of the <see cref="SerializeAccessTokenContext"/> class.
        /// </summary>
        public SerializeAccessTokenContext(
            IOwinContext context,
            OpenIdConnectServerOptions options,
            OpenIdConnectRequest request,
            OpenIdConnectResponse response,
            AuthenticationTicket ticket)
            : base(context, options)
        {
            Request = request;
            Response = response;
            Ticket = ticket;
        }

        /// <summary>
        /// Gets the OpenID Connect request.
        /// </summary>
        public new OpenIdConnectRequest Request { get; }

        /// <summary>
        /// Gets the OpenID Connect response.
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
        /// Gets or sets the scopes associated with the authentication ticket.
        /// </summary>
        public IEnumerable<string> Scopes
        {
            get => Ticket.GetScopes();
            set => Ticket.SetScopes(value);
        }

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
