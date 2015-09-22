/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using Microsoft.IdentityModel.Protocols;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Notifications;

namespace Owin.Security.OpenIdConnect.Server {
    /// <summary>
    /// Provides context information when processing an Authorization Response
    /// </summary>
    public sealed class AuthorizationEndpointResponseContext : BaseNotification<OpenIdConnectServerOptions> {
        /// <summary>
        /// Initializes a new instance of the <see cref="AuthorizationEndpointResponseContext"/> class
        /// </summary>
        /// <param name="context"></param>
        /// <param name="options"></param>
        /// <param name="ticket"></param>
        /// <param name="request"></param>
        /// <param name="response"></param>
        internal AuthorizationEndpointResponseContext(
            IOwinContext context,
            OpenIdConnectServerOptions options,
            AuthenticationTicket ticket,
            OpenIdConnectMessage request,
            OpenIdConnectMessage response)
            : base(context, options) {
            AuthenticationTicket = ticket;
            Request = request;
            Response = response;
        }

        /// <summary>
        /// Gets the authentication ticket containing the
        /// claims representing the authenticated user.
        /// </summary>
        public AuthenticationTicket AuthenticationTicket { get; private set; }

        /// <summary>
        /// Gets the authorization request. 
        /// </summary>
        public new OpenIdConnectMessage Request { get; private set; }

        /// <summary>
        /// Gets the authorization response. 
        /// </summary>
        public new OpenIdConnectMessage Response { get; private set; }

        /// <summary>
        /// Get the access code expected to
        /// be returned to the client application.
        /// Depending on the flow, it can be null.
        /// </summary>
        public string AccessToken {
            get { return Response.AccessToken; }
        }

        /// <summary>
        /// Get the authorization code expected to
        /// be returned to the client application.
        /// Depending on the flow, it can be null.
        /// </summary>
        public string AuthorizationCode {
            get { return Response.Code; }
        }
    }
}
