/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using AspNet.Security.OpenIdConnect.Primitives;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Notifications;

namespace Owin.Security.OpenIdConnect.Server
{
    /// <summary>
    /// Represents the context class associated with the
    /// <see cref="OpenIdConnectServerProvider.ApplyTokenResponse"/> event.
    /// </summary>
    public class ApplyTokenResponseContext : BaseNotification<OpenIdConnectServerOptions>
    {
        /// <summary>
        /// Creates a new instance of the <see cref="ApplyTokenResponseContext"/> class.
        /// </summary>
        public ApplyTokenResponseContext(
            IOwinContext context,
            OpenIdConnectServerOptions options,
            AuthenticationTicket ticket,
            OpenIdConnectRequest request,
            OpenIdConnectResponse response)
            : base(context, options)
        {
            Ticket = ticket;
            Request = request;
            Response = response;
        }

        /// <summary>
        /// Gets the token request.
        /// </summary>
        /// <remarks>
        /// Note: this property may be null if an error occurred while
        /// extracting the token request from the HTTP request.
        /// </remarks>
        public new OpenIdConnectRequest Request { get; }

        /// <summary>
        /// Gets the token response.
        /// </summary>
        public new OpenIdConnectResponse Response { get; }

        /// <summary>
        /// Gets the authentication ticket.
        /// </summary>
        public AuthenticationTicket Ticket { get; }

        /// <summary>
        /// Gets the error code returned to the client application.
        /// When the response indicates a successful response,
        /// this property returns <c>null</c>.
        /// </summary>
        public string Error => Response.Error;
    }
}
