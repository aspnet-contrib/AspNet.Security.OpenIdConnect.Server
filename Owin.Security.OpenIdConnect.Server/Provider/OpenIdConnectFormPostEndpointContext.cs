// Copyright (c) Microsoft Open Technologies, Inc. All rights reserved. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using Microsoft.Owin.Security.OpenIdConnect.Server.Messages;
using Microsoft.Owin.Security.Provider;

namespace Microsoft.Owin.Security.OpenIdConnect.Server {
    public class OpenIdConnectFormPostEndpointContext : EndpointContext<OpenIdConnectServerOptions> {
        /// <summary>
        /// Creates an instance of this context
        /// </summary>
        public OpenIdConnectFormPostEndpointContext(
            IOwinContext context,
            OpenIdConnectServerOptions options,
            FormPostEndpointRequest formPostRequest)
            : base(context, options) {
            if (formPostRequest == null) {
                throw new ArgumentNullException("formPostRequest");
            }

            FormPostRequest = formPostRequest;
        }

        /// <summary>
        /// Gets OpenIdConnect authorization request data.
        /// </summary>
        public FormPostEndpointRequest FormPostRequest { get; private set; }
    }
}
