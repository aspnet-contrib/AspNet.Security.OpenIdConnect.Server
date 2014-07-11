// Copyright (c) Microsoft Open Technologies, Inc. All rights reserved. See License.txt in the project root for license information.

using Microsoft.Owin.Security.Provider;

namespace Microsoft.Owin.Security.OpenIdConnect.Server {
    /// <summary>
    /// Provides context information used when determining the OpenIdConnect flow type based on the request.
    /// </summary>
    public class OpenIdConnectMatchEndpointContext : EndpointContext<OpenIdConnectServerOptions> {
        /// <summary>
        /// Initializes a new instance of the <see cref="OpenIdConnectMatchEndpointContext"/> class
        /// </summary>
        /// <param name="context"></param>
        /// <param name="options"></param>
        public OpenIdConnectMatchEndpointContext(
            IOwinContext context,
            OpenIdConnectServerOptions options)
            : base(context, options) {
        }

        /// <summary>
        /// Gets whether or not the endpoint is an OpenIdConnect authorize endpoint.
        /// </summary>
        public bool IsAuthorizeEndpoint { get; private set; }

        /// <summary>
        /// Gets whether or not the endpoint is an OpenIdConnect token endpoint.
        /// </summary>
        public bool IsTokenEndpoint { get; private set; }

        /// <summary>
        /// Sets the endpoint type to authorize endpoint.
        /// </summary>
        public void MatchesAuthorizeEndpoint() {
            IsAuthorizeEndpoint = true;
            IsTokenEndpoint = false;
        }

        /// <summary>
        /// Sets the endpoint type to token endpoint.
        /// </summary>
        public void MatchesTokenEndpoint() {
            IsAuthorizeEndpoint = false;
            IsTokenEndpoint = true;
        }

        /// <summary>
        /// Sets the endpoint type to neither authorize nor token.
        /// </summary>
        public void MatchesNothing() {
            IsAuthorizeEndpoint = false;
            IsTokenEndpoint = false;
        }
    }
}
