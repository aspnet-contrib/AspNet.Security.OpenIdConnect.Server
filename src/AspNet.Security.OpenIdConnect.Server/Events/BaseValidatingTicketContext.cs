/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Authentication;

namespace AspNet.Security.OpenIdConnect.Server {
    /// <summary>
    /// Base class used for certain event contexts
    /// </summary>
    public abstract class BaseValidatingTicketContext : BaseValidatingContext {
        /// <summary>
        /// Initializes base class used for certain event contexts
        /// </summary>
        protected BaseValidatingTicketContext(
            HttpContext context,
            OpenIdConnectServerOptions options,
            AuthenticationTicket ticket)
            : base(context, options) {
            Ticket = ticket;
        }

        /// <summary>
        /// Replaces the ticket information on this context and marks it as as validated by the application.
        /// IsValidated becomes true and HasError becomes false as a result of calling.
        /// </summary>
        /// <param name="ticket">Assigned to the Ticket property</param>
        /// <returns>True if the validation has taken effect.</returns>
        public bool Validate(AuthenticationTicket ticket) {
            Ticket = ticket;
            return Validate();
        }

        /// <summary>
        /// Alters the ticket information on this context and marks it as as validated by the application.
        /// IsValidated becomes true and HasError becomes false as a result of calling.
        /// </summary>
        /// <param name="principal">Assigned to the Ticket.Principal property</param>
        /// <returns>True if the validation has taken effect.</returns>
        public bool Validate(ClaimsPrincipal principal) {
            var properties = Ticket?.Properties ?? new AuthenticationProperties();
            return Validate(new AuthenticationTicket(principal, properties, Options.AuthenticationScheme));
        }
    }
}
