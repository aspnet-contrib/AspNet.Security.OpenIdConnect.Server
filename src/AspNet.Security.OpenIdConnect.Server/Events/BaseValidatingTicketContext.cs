/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.Security.Claims;
using AspNet.Security.OpenIdConnect.Primitives;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace AspNet.Security.OpenIdConnect.Server
{
    /// <summary>
    /// Represents an abstract base class used for certain event contexts.
    /// </summary>
    public abstract class BaseValidatingTicketContext : BaseValidatingContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="BaseValidatingTicketContext"/> class.
        /// </summary>
        protected BaseValidatingTicketContext(
            HttpContext context,
            AuthenticationScheme scheme,
            OpenIdConnectServerOptions options,
            OpenIdConnectRequest request,
            AuthenticationTicket ticket)
            : base(context, scheme, options, request)
        {
            Ticket = ticket;
        }

        /// <summary>
        /// Gets or sets the authentication ticket that will be
        /// used to generate an authorization or token response.
        /// </summary>
        public AuthenticationTicket Ticket { get; private set; }

        /// <summary>
        /// Validates the request and sets the authentication ticket that
        /// will be used to generate an authorization or token response.
        /// </summary>
        /// <param name="ticket">The authentication ticket.</param>
        public void Validate(AuthenticationTicket ticket)
        {
            if (ticket == null)
            {
                throw new ArgumentNullException(nameof(ticket));
            }

            Ticket = ticket;
            Validate();
        }

        /// <summary>
        /// Validates the request and sets the claims principal that
        /// will be used to generate an authorization or token response.
        /// </summary>
        /// <param name="identity">The claims identity.</param>
        public void Validate(ClaimsIdentity identity) => Validate(new ClaimsPrincipal(identity));

        /// <summary>
        /// Validates the request and sets the claims principal that
        /// will be used to generate an authorization or token response.
        /// </summary>
        /// <param name="principal">The claims principal.</param>
        public void Validate(ClaimsPrincipal principal)
        {
            if (principal == null)
            {
                throw new ArgumentNullException(nameof(principal));
            }

            var properties = Ticket?.Properties ?? new AuthenticationProperties();
            Validate(new AuthenticationTicket(principal, properties, Scheme.Name));
        }
    }
}
