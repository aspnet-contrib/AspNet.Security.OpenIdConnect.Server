/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using AspNet.Security.OpenIdConnect.Extensions;
using Microsoft.AspNetCore.Http;

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
            OpenIdConnectRequest request)
            : base(context, options, request) {
        }

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

        /// <summary>
        /// Sets client_id and marks the context
        /// as validated by the application.
        /// </summary>
        /// <param name="clientId"></param>
        /// <returns></returns>
        public bool Validate(string clientId) {
            ClientId = clientId;

            return Validate();
        }

        /// <summary>
        /// Sets client_id and client_secret and marks
        /// the context as validated by the application.
        /// </summary>
        /// <param name="clientId"></param>
        /// <param name="clientSecret"></param>
        /// <returns></returns>
        public bool Validate(string clientId, string clientSecret) {
            ClientId = clientId;
            ClientSecret = clientSecret;

            return Validate();
        }

        /// <summary>
        /// Resets client_id and client_secret and marks
        /// the context as rejected by the application.
        /// </summary>
        public override bool Reject() {
            ClientId = null;
            ClientSecret = null;

            return base.Reject();
        }
    }
}
