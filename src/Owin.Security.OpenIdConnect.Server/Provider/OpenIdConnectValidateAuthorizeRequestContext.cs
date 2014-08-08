// Copyright (c) Microsoft Open Technologies, Inc. All rights reserved. See License.txt in the project root for license information.

using Microsoft.Owin.Security.OpenIdConnect.Server.Messages;

namespace Microsoft.Owin.Security.OpenIdConnect.Server {
    /// <summary>
    /// Provides context information used in validating an OpenIdConnect authorization request.
    /// </summary>
    public class OpenIdConnectValidateAuthorizeRequestContext : BaseValidatingContext<OpenIdConnectServerOptions> {
        /// <summary>
        /// Initializes a new instance of the <see cref="OpenIdConnectValidateAuthorizeRequestContext"/> class
        /// </summary>
        /// <param name="context"></param>
        /// <param name="options"></param>
        /// <param name="authorizeRequest"></param>
        /// <param name="clientContext"></param>
        public OpenIdConnectValidateAuthorizeRequestContext(
            IOwinContext context,
            OpenIdConnectServerOptions options,
            AuthorizeEndpointRequest authorizeRequest,
            OpenIdConnectValidateClientRedirectUriContext clientContext) : base(context, options) {
            AuthorizeRequest = authorizeRequest;
            ClientContext = clientContext;
        }

        /// <summary>
        /// Gets OpenIdConnect authorization request data.
        /// </summary>
        public AuthorizeEndpointRequest AuthorizeRequest { get; private set; }

        /// <summary>
        /// Gets data about the OpenIdConnect client. 
        /// </summary>
        public OpenIdConnectValidateClientRedirectUriContext ClientContext { get; private set; }
    }
}
