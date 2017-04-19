/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using AspNet.Security.OpenIdConnect.Primitives;
using Microsoft.Owin;

namespace Owin.Security.OpenIdConnect.Server
{
    /// <summary>
    /// Represents the context class associated with the
    /// <see cref="OpenIdConnectServerProvider.HandleAuthorizationRequest"/> event.
    /// </summary>
    public class HandleAuthorizationRequestContext : BaseValidatingTicketContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="HandleAuthorizationRequestContext"/> class.
        /// </summary>
        public HandleAuthorizationRequestContext(
            IOwinContext context,
            OpenIdConnectServerOptions options,
            OpenIdConnectRequest request)
            : base(context, options, request, null)
        {
            Validate();
        }
    }
}
