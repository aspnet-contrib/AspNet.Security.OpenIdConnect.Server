/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System.Collections.Generic;
using AspNet.Security.OpenIdConnect.Primitives;
using Microsoft.IdentityModel.Protocols;
using Microsoft.Owin;

namespace Owin.Security.OpenIdConnect.Server
{
    /// <summary>
    /// An event raised before the authorization server handles
    /// the request made to the JWKS metadata endpoint.
    /// </summary>
    public class HandleCryptographyRequestContext : BaseValidatingContext
    {
        /// <summary>
        /// Creates an instance of this context.
        /// </summary>
        public HandleCryptographyRequestContext(
            IOwinContext context,
            OpenIdConnectServerOptions options,
            OpenIdConnectRequest request)
            : base(context, options, request)
        {
            Validate();
        }

        /// <summary>
        /// Gets a list of the JSON Web Keys found by the authorization server.
        /// </summary>
        public IList<JsonWebKey> Keys { get; } = new List<JsonWebKey>();
    }
}
