/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using Microsoft.AspNet.Http;
using Microsoft.IdentityModel.Protocols;

namespace AspNet.Security.OpenIdConnect.Server {
    /// <summary>
    /// Base class used for certain event contexts
    /// </summary>
    public abstract class BaseValidatingClientNotification : BaseValidatingNotification<OpenIdConnectServerOptions> {
        /// <summary>
        /// Initializes base class used for certain event contexts
        /// </summary>
        protected BaseValidatingClientNotification(
            HttpContext context,
            OpenIdConnectServerOptions options,
            OpenIdConnectMessage request)
            : base(context, options) {
            AuthorizationRequest = request;
        }

        /// <summary>
        /// Gets the authorization request. 
        /// </summary>
        public OpenIdConnectMessage AuthorizationRequest { get; }

        /// <summary>
        /// The "client_id" parameter for the current request.
        /// The authorization server application is responsible for 
        /// validating this value to ensure it identifies a registered client.
        /// </summary>
        public string ClientId {
            get { return AuthorizationRequest.ClientId; }
            set { AuthorizationRequest.ClientId = value; }
        }
    }
}
