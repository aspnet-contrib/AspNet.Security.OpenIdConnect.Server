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
    public class ApplyAuthorizationResponseContext : BaseNotification<OpenIdConnectServerOptions> {
        /// <summary>
        /// Initializes a new instance of the <see cref="ApplyAuthorizationResponseContext"/> class
        /// </summary>
        /// <param name="context"></param>
        /// <param name="options"></param>
        /// <param name="ticket"></param>
        /// <param name="request"></param>
        /// <param name="response"></param>
        public ApplyAuthorizationResponseContext(
            IOwinContext context,
            OpenIdConnectServerOptions options,
            AuthenticationTicket ticket,
            OpenIdConnectMessage request,
            OpenIdConnectMessage response)
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
        /// Gets the authorization request. 
        /// </summary>
        public new OpenIdConnectMessage Request { get; }

        /// <summary>
        /// Gets the authorization response. 
        /// </summary>
        public new OpenIdConnectMessage Response { get; }

        /// <summary>
        /// Gets the access code expected to
        /// be returned to the client application.
        /// Depending on the flow, it can be null.
        /// </summary>
        public string AccessToken => Response.AccessToken;

        /// <summary>
        /// Gets the authorization code expected to
        /// be returned to the client application.
        /// Depending on the flow, it can be null.
        /// </summary>
        public string AuthorizationCode => Response.Code;

        /// <summary>
        /// Gets the error code returned to the client application.
        /// When the response indicates a successful response,
        /// this property returns <c>null</c>.
        /// </summary>
        public string Error => Response.Error;
    }
}
