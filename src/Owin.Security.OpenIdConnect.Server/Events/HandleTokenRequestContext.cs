/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using AspNet.Security.OpenIdConnect.Primitives;
using Microsoft.Owin;
using Microsoft.Owin.Security;

namespace Owin.Security.OpenIdConnect.Server
{
    /// <summary>
    /// Represents the context class associated with the
    /// <see cref="OpenIdConnectServerProvider.HandleTokenRequest"/> event.
    /// </summary>
    public class HandleTokenRequestContext : BaseValidatingTicketContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="HandleTokenRequestContext"/> class.
        /// </summary>
        public HandleTokenRequestContext(
            IOwinContext context,
            OpenIdConnectServerOptions options,
            OpenIdConnectRequest request,
            AuthenticationTicket ticket)
            : base(context, options, request, ticket)
        {
            Validate();
        }
    }
}
