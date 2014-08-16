/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/AspNet-OpenIdConnect-Server/Owin.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using Microsoft.Owin;

namespace Owin.Security.OpenIdConnect.Server {
    /// <summary>
    /// Base class used for certain event contexts
    /// </summary>
    public abstract class BaseValidatingClientContext : BaseValidatingContext<OpenIdConnectServerOptions> {
        /// <summary>
        /// Initializes base class used for certain event contexts
        /// </summary>
        protected BaseValidatingClientContext(
            IOwinContext context,
            OpenIdConnectServerOptions options,
            string clientId)
            : base(context, options) {
            ClientId = clientId;
        }

        /// <summary>
        /// The "client_id" parameter for the current request. The Authorization Server application is responsible for 
        /// validating this value identifies a registered client.
        /// </summary>
        public string ClientId { get; protected set; }
    }
}
