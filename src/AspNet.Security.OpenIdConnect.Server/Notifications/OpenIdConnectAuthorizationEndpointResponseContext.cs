/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/AspNet-OpenIdConnect-Server/Owin.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.Security.Claims;
using Microsoft.AspNet.Authentication;
using Microsoft.AspNet.Authentication.Notifications;
using Microsoft.AspNet.Http;
using Microsoft.AspNet.Http.Authentication;
using Microsoft.IdentityModel.Protocols;

namespace AspNet.Security.OpenIdConnect.Server {
    /// <summary>
    /// Provides context information when processing an Authorization Response
    /// </summary>
    public sealed class OpenIdConnectAuthorizationEndpointResponseContext : EndpointContext<OpenIdConnectServerOptions> {
        /// <summary>
        /// Initializes a new instance of the <see cref="OpenIdConnectAuthorizationEndpointResponseContext"/> class
        /// </summary>
        /// <param name="context"></param>
        /// <param name="options"></param>
        /// <param name="ticket"></param>
        /// <param name="authorizationRequest"></param>
        /// <param name="authorizationResponse"></param>
        internal OpenIdConnectAuthorizationEndpointResponseContext(
            HttpContext context,
            OpenIdConnectServerOptions options,
            AuthenticationTicket ticket,
            OpenIdConnectMessage authorizationRequest,
            OpenIdConnectMessage authorizationResponse)
            : base(context, options) {
            if (ticket == null) {
                throw new ArgumentNullException("ticket");
            }

            Principal = ticket.Principal;
            Properties = ticket.Properties;
            AuthorizationRequest = authorizationRequest;
            AuthorizationResponse = authorizationResponse;
        }

        /// <summary>
        /// Gets the principal of the resource owner.
        /// </summary>
        public ClaimsPrincipal Principal { get; }

        /// <summary>
        /// Dictionary containing the state of the authentication session.
        /// </summary>
        public AuthenticationProperties Properties { get; }

        /// <summary>
        /// Gets the authorization request. 
        /// </summary>
        public OpenIdConnectMessage AuthorizationRequest { get; }

        /// <summary>
        /// Gets the authorization response. 
        /// </summary>
        public OpenIdConnectMessage AuthorizationResponse { get; }

        /// <summary>
        /// Get the access code expected to
        /// be returned to the client application.
        /// Depending on the flow, it can be null.
        /// </summary>
        public string AccessToken {
            get { return AuthorizationResponse.AccessToken; }
        }

        /// <summary>
        /// Get the authorization code expected to
        /// be returned to the client application.
        /// Depending on the flow, it can be null.
        /// </summary>
        public string AuthorizationCode {
            get { return AuthorizationResponse.Code; }
        }
    }
}
