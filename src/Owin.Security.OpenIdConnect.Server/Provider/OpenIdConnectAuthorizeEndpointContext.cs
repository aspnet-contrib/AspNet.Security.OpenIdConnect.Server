// Copyright (c) Microsoft Open Technologies, Inc. All rights reserved. See License.txt in the project root for license information.

using Microsoft.Owin.Security.OpenIdConnect.Server.Messages;
using Microsoft.Owin.Security.Provider;

namespace Microsoft.Owin.Security.OpenIdConnect.Server {
    /// <summary>
    /// An event raised after the Authorization Server has processed the request, but before it is passed on to the web application.
    /// Calling RequestCompleted will prevent the request from passing on to the web application.
    /// </summary>
    public class OpenIdConnectAuthorizeEndpointContext : EndpointContext<OpenIdConnectServerOptions> {
        /// <summary>
        /// Creates an instance of this context
        /// </summary>
        public OpenIdConnectAuthorizeEndpointContext(
            IOwinContext context,
            OpenIdConnectServerOptions options,
            AuthorizeEndpointRequest authorizeRequest)
            : base(context, options) {
            AuthorizeRequest = authorizeRequest;
        }

        /// <summary>
        /// Gets OpenIdConnect authorization request data.
        /// </summary>
        public AuthorizeEndpointRequest AuthorizeRequest { get; private set; }
    }
}
