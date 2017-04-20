/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using AspNet.Security.OpenIdConnect.Primitives;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace AspNet.Security.OpenIdConnect.Server
{
    /// <summary>
    /// Represents the context class associated with the
    /// <see cref="OpenIdConnectServerProvider.ValidateRevocationRequest"/> event.
    /// </summary>
    public class ValidateRevocationRequestContext : BaseValidatingClientContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="ValidateRevocationRequestContext"/> class.
        /// </summary>
        public ValidateRevocationRequestContext(
            HttpContext context,
            AuthenticationScheme scheme,
            OpenIdConnectServerOptions options,
            OpenIdConnectRequest request)
            : base(context, scheme, options, request)
        {
        }

        /// <summary>
        /// Gets the optional token_type_hint parameter extracted from the
        /// revocation request, or <c>null</c> if it cannot be found.
        /// </summary>
        public string TokenTypeHint => Request.TokenTypeHint;
    }
}
