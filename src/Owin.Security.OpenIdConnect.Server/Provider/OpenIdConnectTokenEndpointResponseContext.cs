/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/AspNet-OpenIdConnect-Server/Owin.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.Security.Claims;
using Microsoft.IdentityModel.Protocols;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;
using Newtonsoft.Json.Linq;

namespace Owin.Security.OpenIdConnect.Server {
    /// <summary>
    /// Provides context information used at the end of a token-endpoint-request.
    /// </summary>
    public sealed class OpenIdConnectTokenEndpointResponseContext : EndpointContext<OpenIdConnectServerOptions> {
        /// <summary>
        /// Initializes a new instance of the <see cref="OpenIdConnectTokenEndpointResponseContext"/> class
        /// </summary>
        /// <param name="context"></param>
        /// <param name="options"></param>
        /// <param name="ticket"></param>
        /// <param name="tokenRequest"></param>
        /// <param name="tokenResponse"></param>
        internal OpenIdConnectTokenEndpointResponseContext(
            IOwinContext context,
            OpenIdConnectServerOptions options,
            AuthenticationTicket ticket,
            OpenIdConnectMessage tokenRequest,
            OpenIdConnectMessage tokenResponse)
            : base(context, options) {
            if (ticket == null) {
                throw new ArgumentNullException("ticket");
            }

            AdditionalParameters = new Dictionary<string, JToken>(StringComparer.Ordinal);
            Identity = ticket.Identity;
            Properties = ticket.Properties;
            TokenIssued = Identity != null;
            TokenRequest = tokenRequest;
            TokenResponse = tokenResponse;
        }

        /// <summary>
        /// Enables additional values to be appended to the token response.
        /// </summary>
        public IDictionary<string, JToken> AdditionalParameters { get; private set; }

        /// <summary>
        /// Gets the identity of the resource owner.
        /// </summary>
        public ClaimsIdentity Identity { get; private set; }

        /// <summary>
        /// Dictionary containing the state of the authentication session.
        /// </summary>
        public AuthenticationProperties Properties { get; private set; }

        /// <summary>
        /// The issued Access-Token
        /// </summary>
        public string AccessToken {
            get { return TokenResponse.AccessToken; }
        }

        /// <summary>
        /// Gets the token request. 
        /// </summary>
        public OpenIdConnectMessage TokenRequest { get; private set; }

        /// <summary>
        /// Gets the token response. 
        /// </summary>
        public OpenIdConnectMessage TokenResponse { get; private set; }

        /// <summary>
        /// Gets whether or not the token should be issued.
        /// </summary>
        public bool TokenIssued { get; private set; }

        /// <summary>
        /// Issues the token.
        /// </summary>
        /// <param name="identity"></param>
        /// <param name="properties"></param>
        public void Issue(ClaimsIdentity identity, AuthenticationProperties properties) {
            Identity = identity;
            Properties = properties;
            TokenIssued = true;
        }
    }
}
