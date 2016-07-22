/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using Microsoft.Owin;
using Owin.Security.OpenIdConnect.Extensions;

namespace Owin.Security.OpenIdConnect.Server {
    /// <summary>
    /// Provides context information used when validating a token request.
    /// </summary>
    public class ValidateTokenRequestContext : BaseValidatingClientContext {
        /// <summary>
        /// Initializes a new instance of the <see cref="ValidateTokenRequestContext"/> class.
        /// </summary>
        /// <param name="context"></param>
        /// <param name="options"></param>
        /// <param name="request"></param>
        public ValidateTokenRequestContext(
            IOwinContext context,
            OpenIdConnectServerOptions options,
            OpenIdConnectRequest request)
            : base(context, options, request) {
        }
    }
}
