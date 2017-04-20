/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System.Collections.Generic;
using AspNet.Security.OpenIdConnect.Primitives;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Owin.Security.OpenIdConnect.Extensions;

namespace Owin.Security.OpenIdConnect.Server
{
    /// <summary>
    /// Represents the context class associated with the
    /// <see cref="OpenIdConnectServerProvider.SerializeAuthorizationCode"/> event.
    /// </summary>
    public class SerializeAuthorizationCodeContext : BaseSerializingContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="SerializeAuthorizationCodeContext"/> class.
        /// </summary>
        public SerializeAuthorizationCodeContext(
            IOwinContext context,
            OpenIdConnectServerOptions options,
            OpenIdConnectRequest request,
            OpenIdConnectResponse response,
            AuthenticationTicket ticket)
            : base(context, options, request, response, ticket)
        {
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
        /// Gets or sets the data format used to serialize the authentication ticket.
        /// </summary>
        public ISecureDataFormat<AuthenticationTicket> DataFormat { get; set; }

        /// <summary>
        /// Gets or sets the authorization code returned to the client application.
        /// </summary>
        public string AuthorizationCode { get; set; }
    }
}
