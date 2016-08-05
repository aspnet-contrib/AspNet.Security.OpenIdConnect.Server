/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using AspNet.Security.OpenIdConnect.Extensions;
using Microsoft.AspNetCore.Http;

namespace AspNet.Security.OpenIdConnect.Server {
    /// <summary>
    /// An event raised after the Authorization Server has processed the request, but before it is passed on to the web application.
    /// Calling RequestCompleted will prevent the request from passing on to the web application.
    /// </summary>
    public class HandleAuthorizationRequestContext : BaseValidatingTicketContext {
        /// <summary>
        /// Creates an instance of this context
        /// </summary>
        public HandleAuthorizationRequestContext(
            HttpContext context,
            OpenIdConnectServerOptions options,
            OpenIdConnectRequest request)
            : base(context, options, null) {
            Request = request;
            Validate();
        }

        /// <summary>
        /// Gets the authorization request.
        /// </summary>
        public new OpenIdConnectRequest Request { get; }
    }
}
