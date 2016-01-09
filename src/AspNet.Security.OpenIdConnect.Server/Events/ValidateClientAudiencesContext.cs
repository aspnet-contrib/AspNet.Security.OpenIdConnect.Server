/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System.Collections.Generic;
using AspNet.Security.OpenIdConnect.Extensions;
using Microsoft.AspNet.Authentication;
using Microsoft.AspNet.Http;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace AspNet.Security.OpenIdConnect.Server {
    /// <summary>
    /// Contains information about the client audiences.
    /// </summary>
    public sealed class ValidateClientAudiencesContext : BaseValidatingClientContext {

        private readonly AuthenticationTicket _ticket;

        /// <summary>
        /// Initializes a new instance of the <see cref="ValidateClientAudiencesContext"/> class
        /// </summary>
        /// <param name="context"></param>
        /// <param name="options"></param>
        /// <param name="request"></param>
        /// <param name="ticket"></param>
        internal ValidateClientAudiencesContext(
            HttpContext context,
            OpenIdConnectServerOptions options,
            OpenIdConnectMessage request,
            AuthenticationTicket ticket)
            : base(context, options, request) {
            _ticket = ticket;
            Skip();
        }

        /// <summary>
        /// Gets the intended audiences of the authentication ticket.
        /// </summary>
        public IEnumerable<string> Audiences => _ticket.GetAudiences();
    }
}
