/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using AspNet.Security.OpenIdConnect.Extensions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace AspNet.Security.OpenIdConnect.Server {
    /// <summary>
    /// An event raised before the authorization server starts
    /// writing the configuration metadata to the response stream.
    /// </summary>
    public class ApplyConfigurationResponseContext : BaseControlContext {
        /// <summary>
        /// Creates an instance of this context.
        /// </summary>
        public ApplyConfigurationResponseContext(
            HttpContext context,
            OpenIdConnectServerOptions options,
            OpenIdConnectRequest request,
            OpenIdConnectResponse response)
            : base(context) {
            Options = options;
            Request = request;
            Response = response;
        }

        /// <summary>
        /// Gets the options used by the OpenID Connect server.
        /// </summary>
        public OpenIdConnectServerOptions Options { get; }

        /// <summary>
        /// Gets the configuration request.
        /// </summary>
        public new OpenIdConnectRequest Request { get; }

        /// <summary>
        /// Gets the response returned to the client application.
        /// </summary>
        public new OpenIdConnectResponse Response { get; }

        /// <summary>
        /// Gets the error code returned to the client application.
        /// When the response indicates a successful response,
        /// this property returns <c>null</c>.
        /// </summary>
        public string Error => Response.Error;
    }
}
