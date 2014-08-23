/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/AspNet-OpenIdConnect-Server/Owin.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.Security.Claims;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;
using Owin.Security.OpenIdConnect.Server.Messages;

namespace Owin.Security.OpenIdConnect.Server {
    /// <summary>
    /// Provides context information when processing an Authorization Response
    /// </summary>
    public class OpenIdConnectAuthorizationEndpointResponseContext : EndpointContext<OpenIdConnectServerOptions> {
        /// <summary>
        /// Initializes a new instance of the <see cref="OpenIdConnectAuthorizationEndpointResponseContext"/> class
        /// </summary>
        /// <param name="context"></param>
        /// <param name="options"></param>
        /// <param name="ticket"></param>
        /// <param name="authorizationEndpointRequest"></param>
        /// <param name="accessToken"></param>
        /// <param name="authorizationCode"></param>
        public OpenIdConnectAuthorizationEndpointResponseContext(
            IOwinContext context,
            OpenIdConnectServerOptions options,
            AuthenticationTicket ticket,
            OpenIdConnectAuthorizationRequest authorizationEndpointRequest,
            string accessToken,
            string authorizationCode)
            : base(context, options) {
            if (ticket == null) {
                throw new ArgumentNullException("ticket");
            }

            Identity = ticket.Identity;
            Properties = ticket.Properties;
            AuthorizationRequest = authorizationEndpointRequest;
            AdditionalResponseParameters = new Dictionary<string, string>(StringComparer.Ordinal);
            AccessToken = accessToken;
            AuthorizationCode = authorizationCode;
        }

        /// <summary>
        /// Gets the identity of the resource owner.
        /// </summary>
        public ClaimsIdentity Identity { get; private set; }

        /// <summary>
        /// Dictionary containing the state of the authentication session.
        /// </summary>
        public AuthenticationProperties Properties { get; private set; }

        /// <summary>
        /// Gets information about the authorization request. 
        /// </summary>
        public OpenIdConnectAuthorizationRequest AuthorizationRequest { get; private set; }

        /// <summary>
        /// Enables additional values to be appended to the token response.
        /// </summary>
        public IDictionary<string, string> AdditionalResponseParameters { get; private set; }

        /// <summary>
        /// The serialized Access-Token. Depending on the flow, it can be null.
        /// </summary>
        public string AccessToken { get; private set; }

        /// <summary>
        /// The created Authorization-Code. Depending on the flow, it can be null.
        /// </summary>
        public string AuthorizationCode { get; private set; }
    }
}
