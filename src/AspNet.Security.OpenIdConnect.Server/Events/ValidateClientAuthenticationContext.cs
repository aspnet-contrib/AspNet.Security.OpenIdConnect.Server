/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using Microsoft.AspNet.Http;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace AspNet.Security.OpenIdConnect.Server {
    /// <summary>
    /// Contains information about the client credentials.
    /// </summary>
    public sealed class ValidateClientAuthenticationContext : BaseValidatingClientContext {
        /// <summary>
        /// Initializes a new instance of the <see cref="ValidateClientAuthenticationContext"/> class
        /// </summary>
        /// <param name="context"></param>
        /// <param name="options"></param>
        /// <param name="request"></param>
        internal ValidateClientAuthenticationContext(
            HttpContext context,
            OpenIdConnectServerOptions options,
            OpenIdConnectMessage request)
            : base(context, options, request) {
        }

        /// <summary>
        /// Sets client_id and marks the context
        /// as validated by the application.
        /// </summary>
        /// <param name="clientId"></param>
        /// <returns></returns>
        public bool Validated(string clientId) {
            ClientId = clientId;

            return Validated();
        }

        /// <summary>
        /// Sets client_id and client_secret and marks
        /// the context as validated by the application.
        /// </summary>
        /// <param name="clientId"></param>
        /// <param name="clientSecret"></param>
        /// <returns></returns>
        public bool Validated(string clientId, string clientSecret) {
            ClientId = clientId;
            ClientSecret = clientSecret;

            return Validated();
        }

        /// <summary>
        /// Resets client_id and client_secret and marks
        /// the context as rejected by the application.
        /// </summary>
        public override bool Rejected() {
            ClientId = null;
            ClientSecret = null;

            return base.Rejected();
        }
    }
}
