/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using AspNet.Security.OpenIdConnect.Primitives;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Notifications;

namespace Owin.Security.OpenIdConnect.Server {
    /// <summary>
    /// Provides context information used at the end of a token-endpoint-request.
    /// </summary>
    public class ApplyTokenResponseContext : BaseNotification<OpenIdConnectServerOptions> {
        /// <summary>
        /// Initializes a new instance of the <see cref="ApplyTokenResponseContext"/> class
        /// </summary>
        /// <param name="context"></param>
        /// <param name="options"></param>
        /// <param name="ticket"></param>
        /// <param name="request"></param>
        /// <param name="response"></param>
        public ApplyTokenResponseContext(
            IOwinContext context,
            OpenIdConnectServerOptions options,
            AuthenticationTicket ticket,
            OpenIdConnectRequest request,
            OpenIdConnectResponse response)
            : base(context, options) {
            Ticket = ticket;
            Request = request;
            Response = response;
        }

        /// <summary>
        /// Gets the authentication ticket containing the
        /// claims representing the authenticated user.
        /// </summary>
        public AuthenticationTicket Ticket { get; }

        /// <summary>
        /// Gets the token request.
        /// </summary>
        /// <remarks>
        /// Note: this property may be null if an error occurred when
        /// extracting the token request from the HTTP request.
        /// </remarks>
        public new OpenIdConnectRequest Request { get; }

        /// <summary>
        /// Gets the token response.
        /// </summary>
        public new OpenIdConnectResponse Response { get; }

        /// <summary>
        /// Gets the error code returned to the client application.
        /// When the response indicates a successful response,
        /// this property returns <c>null</c>.
        /// </summary>
        public string Error => Response.Error;
    }
}
