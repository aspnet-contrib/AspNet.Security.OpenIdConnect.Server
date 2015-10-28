/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using Microsoft.AspNet.Http;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace AspNet.Security.OpenIdConnect.Server {
    /// <summary>
    /// Base class used for certain event contexts
    /// </summary>
    public abstract class BaseValidatingClientContext : BaseValidatingContext {
        /// <summary>
        /// Initializes base class used for certain event contexts
        /// </summary>
        protected BaseValidatingClientContext(
            HttpContext context,
            OpenIdConnectServerOptions options,
            OpenIdConnectMessage request)
            : base(context, options) {
            Request = request;
        }

        /// <summary>
        /// Gets the authorization request. 
        /// </summary>
        public new OpenIdConnectMessage Request { get; }

        /// <summary>
        /// The "client_id" parameter for the current request.
        /// The authorization server application is responsible for 
        /// validating this value to ensure it identifies a registered client.
        /// </summary>
        public string ClientId {
            get { return Request.ClientId; }
            set { Request.ClientId = value; }
        }

        /// <summary>
        /// The "client_secret" parameter for the current request.
        /// The authorization server application is responsible for 
        /// validating this value to ensure it identifies a registered client.
        /// </summary>
        public string ClientSecret {
            get { return Request.ClientSecret; }
            set { Request.ClientSecret = value; }
        }
    }
}
