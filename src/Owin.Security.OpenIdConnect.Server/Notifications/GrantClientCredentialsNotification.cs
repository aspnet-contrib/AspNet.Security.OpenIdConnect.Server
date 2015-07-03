/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System.Collections.Generic;
using System.Linq;
using Microsoft.IdentityModel.Protocols;
using Microsoft.Owin;

namespace Owin.Security.OpenIdConnect.Server {
    /// <summary>
    /// Provides context information used in handling an OpenIdConnect client credentials grant.
    /// </summary>
    public sealed class GrantClientCredentialsNotification : BaseValidatingTicketNotification<OpenIdConnectServerOptions> {
        /// <summary>
        /// Initializes a new instance of the <see cref="GrantClientCredentialsNotification"/> class
        /// </summary>
        /// <param name="context"></param>
        /// <param name="options"></param>
        /// <param name="request"></param>
        internal GrantClientCredentialsNotification(
            IOwinContext context,
            OpenIdConnectServerOptions options,
            OpenIdConnectMessage request)
            : base(context, options, null) {
            TokenRequest = request;
        }

        /// <summary>
        /// Gets the client_id parameter.
        /// </summary>
        public string ClientId {
            get { return TokenRequest.ClientId; }
        }

        /// <summary>
        /// Gets the list of scopes requested by the client application.
        /// </summary>
        public IEnumerable<string> Scope {
            get {
                if (string.IsNullOrEmpty(TokenRequest.Scope)) {
                    return Enumerable.Empty<string>();
                }

                return TokenRequest.Scope.Split(' ');
            }
        }

        /// <summary>
        /// Gets the token request.
        /// </summary>
        public OpenIdConnectMessage TokenRequest { get; private set; }
    }
}
