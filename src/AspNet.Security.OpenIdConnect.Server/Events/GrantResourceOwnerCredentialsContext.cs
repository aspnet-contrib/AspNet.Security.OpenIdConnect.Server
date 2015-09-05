/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System.Collections.Generic;
using System.Linq;
using Microsoft.AspNet.Http;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace AspNet.Security.OpenIdConnect.Server {
    /// <summary>
    /// Provides context information used in handling an OpenIdConnect resource owner grant.
    /// </summary>
    public sealed class GrantResourceOwnerCredentialsContext : BaseValidatingTicketContext<OpenIdConnectServerOptions> {
        /// <summary>
        /// Initializes a new instance of the <see cref="GrantResourceOwnerCredentialsContext"/> class
        /// </summary>
        /// <param name="context"></param>
        /// <param name="options"></param>
        /// <param name="request"></param>
        internal GrantResourceOwnerCredentialsContext(
            HttpContext context,
            OpenIdConnectServerOptions options,
            OpenIdConnectMessage request)
            : base(context, options, null) {
            Request = request;
        }

        /// <summary>
        /// OpenIdConnect client id.
        /// </summary>
        public string ClientId => Request.ClientId;

        /// <summary>
        /// Resource owner username.
        /// </summary>
        public string UserName => Request.Username;

        /// <summary>
        /// Resource owner password.
        /// </summary>
        public string Password => Request.Password;

        /// <summary>
        /// Gets the list of scopes requested by the client application.
        /// </summary>
        public IEnumerable<string> Scope {
            get {
                if (string.IsNullOrEmpty(Request.Scope)) {
                    return Enumerable.Empty<string>();
                }

                return Request.Scope.Split(' ');
            }
        }

        /// <summary>
        /// Gets the token request.
        /// </summary>
        public new OpenIdConnectMessage Request { get; }
    }
}
