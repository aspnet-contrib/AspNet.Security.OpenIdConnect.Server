/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using Microsoft.AspNet.Authentication;
using Microsoft.AspNet.Http;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace AspNet.Security.OpenIdConnect.Server {
    /// <summary>
    /// Provides context information when processing an Authorization Response
    /// </summary>
    public sealed class AuthorizationEndpointResponseContext : BaseControlContext {

        /// <summary>
        /// Initializes a new instance of the <see cref="AuthorizationEndpointResponseContext"/> class
        /// </summary>
        /// <param name="context"></param>
        /// <param name="options"></param>
        /// <param name="ticket"></param>
        /// <param name="request"></param>
        /// <param name="response"></param>
        internal AuthorizationEndpointResponseContext(
            HttpContext context,
            OpenIdConnectServerOptions options,
            AuthenticationTicket ticket,
            OpenIdConnectMessage request,
            OpenIdConnectMessage response)
            : base(context) {
            Options = options;
            AuthenticationTicket = ticket;
            Request = request;
            Response = response;
        }

        /// <summary>
        /// Gets the options used by the OpenID Connect server.
        /// </summary>
        public OpenIdConnectServerOptions Options { get; }

        /// <summary>
        /// Gets the authorization request. 
        /// </summary>
        public new OpenIdConnectMessage Request { get; }

        /// <summary>
        /// Gets the authorization response. 
        /// </summary>
        public new OpenIdConnectMessage Response { get; }

        /// <summary>
        /// Get the access code expected to
        /// be returned to the client application.
        /// Depending on the flow, it can be null.
        /// </summary>
        public string AccessToken => Response.AccessToken;

        /// <summary>
        /// Get the authorization code expected to
        /// be returned to the client application.
        /// Depending on the flow, it can be null.
        /// </summary>
        public string AuthorizationCode => Response.Code;
    }
}
