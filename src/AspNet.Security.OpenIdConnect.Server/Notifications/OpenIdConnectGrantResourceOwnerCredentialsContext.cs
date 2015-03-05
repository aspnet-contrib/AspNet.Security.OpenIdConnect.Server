/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/AspNet-OpenIdConnect-Server/Owin.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System.Collections.Generic;
using System.Linq;
using Microsoft.AspNet.Http;
using Microsoft.IdentityModel.Protocols;

namespace AspNet.Security.OpenIdConnect.Server {
    /// <summary>
    /// Provides context information used in handling an OpenIdConnect resource owner grant.
    /// </summary>
    public sealed class OpenIdConnectGrantResourceOwnerCredentialsContext : BaseValidatingTicketContext<OpenIdConnectServerOptions> {
        /// <summary>
        /// Initializes a new instance of the <see cref="OpenIdConnectGrantResourceOwnerCredentialsContext"/> class
        /// </summary>
        /// <param name="context"></param>
        /// <param name="options"></param>
        /// <param name="tokenRequest"></param>
        internal OpenIdConnectGrantResourceOwnerCredentialsContext(
            HttpContext context,
            OpenIdConnectServerOptions options,
            OpenIdConnectMessage tokenRequest)
            : base(context, options, null) {
            TokenRequest = tokenRequest;
        }

        /// <summary>
        /// OpenIdConnect client id.
        /// </summary>
        public string ClientId {
            get { return TokenRequest.ClientId; }
        }

        /// <summary>
        /// Resource owner username.
        /// </summary>
        public string UserName {
            get { return TokenRequest.Username; }
        }

        /// <summary>
        /// Resource owner password.
        /// </summary>
        public string Password {
            get { return TokenRequest.Password; }
        }

        /// <summary>
        /// Gets the list of scopes requested by the client application.
        /// </summary>
        public IEnumerable<string> Scope {
            get {
                if (string.IsNullOrWhiteSpace(TokenRequest.Scope)) {
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
