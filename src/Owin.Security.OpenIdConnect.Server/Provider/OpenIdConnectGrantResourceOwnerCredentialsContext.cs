// Copyright (c) Microsoft Open Technologies, Inc. All rights reserved. See License.txt in the project root for license information.

using System.Collections.Generic;

namespace Microsoft.Owin.Security.OpenIdConnect.Server {
    /// <summary>
    /// Provides context information used in handling an OpenIdConnect resource owner grant.
    /// </summary>
    public class OpenIdConnectGrantResourceOwnerCredentialsContext : BaseValidatingTicketContext<OpenIdConnectServerOptions> {
        /// <summary>
        /// Initializes a new instance of the <see cref="OpenIdConnectGrantResourceOwnerCredentialsContext"/> class
        /// </summary>
        /// <param name="context"></param>
        /// <param name="options"></param>
        /// <param name="clientId"></param>
        /// <param name="userName"></param>
        /// <param name="password"></param>
        /// <param name="scope"></param>
        public OpenIdConnectGrantResourceOwnerCredentialsContext(
            IOwinContext context,
            OpenIdConnectServerOptions options,
            string clientId,
            string userName,
            string password,
            IList<string> scope)
            : base(context, options, null) {
            ClientId = clientId;
            UserName = userName;
            Password = password;
            Scope = scope;
        }

        /// <summary>
        /// OpenIdConnect client id.
        /// </summary>
        public string ClientId { get; private set; }

        /// <summary>
        /// Resource owner username.
        /// </summary>
        public string UserName { get; private set; }

        /// <summary>
        /// Resource owner password.
        /// </summary>
        public string Password { get; private set; }

        /// <summary>
        /// List of scopes allowed by the resource owner.
        /// </summary>
        public IList<string> Scope { get; private set; }
    }
}
