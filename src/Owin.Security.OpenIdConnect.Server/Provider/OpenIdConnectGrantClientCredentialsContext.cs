/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/AspNet-OpenIdConnect-Server/Owin.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System.Collections.Generic;
using Microsoft.Owin;

namespace Owin.Security.OpenIdConnect.Server {
    /// <summary>
    /// Provides context information used in handling an OpenIdConnect client credentials grant.
    /// </summary>
    public class OpenIdConnectGrantClientCredentialsContext : BaseValidatingTicketContext<OpenIdConnectServerOptions> {
        /// <summary>
        /// Initializes a new instance of the <see cref="OpenIdConnectGrantClientCredentialsContext"/> class
        /// </summary>
        /// <param name="context"></param>
        /// <param name="options"></param>
        /// <param name="clientId"></param>
        /// <param name="scope"></param>
        public OpenIdConnectGrantClientCredentialsContext(
            IOwinContext context,
            OpenIdConnectServerOptions options,
            string clientId,
            IList<string> scope)
            : base(context, options, null) {
            ClientId = clientId;
            Scope = scope;
        }

        /// <summary>
        /// OpenIdConnect client id.
        /// </summary>
        public string ClientId { get; private set; }

        /// <summary>
        /// List of scopes allowed by the resource owner.
        /// </summary>
        public IList<string> Scope { get; private set; }
    }
}
