/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using AspNet.Security.OpenIdConnect.Extensions;
using Microsoft.AspNetCore.Http;

namespace AspNet.Security.OpenIdConnect.Server {
    /// <summary>
    /// Provides context information used when validating a discovery request.
    /// </summary>
    public class ValidateConfigurationRequestContext : BaseValidatingContext {
        /// <summary>
        /// Initializes a new instance of the <see cref="ValidateConfigurationRequestContext"/> class.
        /// </summary>
        /// <param name="context"></param>
        /// <param name="options"></param>
        /// <param name="request"></param>
        public ValidateConfigurationRequestContext(
            HttpContext context,
            OpenIdConnectServerOptions options,
            OpenIdConnectRequest request)
            : base(context, options, request) {
            Validate();
        }
    }
}
