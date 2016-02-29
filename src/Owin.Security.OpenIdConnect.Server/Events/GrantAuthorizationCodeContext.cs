/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using Microsoft.IdentityModel.Protocols;
using Microsoft.Owin;
using Microsoft.Owin.Security;

namespace Owin.Security.OpenIdConnect.Server {
    /// <summary>
    /// Provides context information when handling an OpenIdConnect authorization code grant.
    /// </summary>
    public class GrantAuthorizationCodeContext : BaseValidatingTicketContext {
        /// <summary>
        /// Initializes a new instance of the <see cref="GrantAuthorizationCodeContext"/> class
        /// </summary>
        /// <param name="context"></param>
        /// <param name="options"></param>
        /// <param name="request"></param>
        /// <param name="ticket"></param>
        public GrantAuthorizationCodeContext(
            IOwinContext context,
            OpenIdConnectServerOptions options,
            OpenIdConnectMessage request,
            AuthenticationTicket ticket)
            : base(context, options, ticket) {
            Request = request;
            Validate();
        }

        /// <summary>
        /// Gets the token request.
        /// </summary>
        public new OpenIdConnectMessage Request { get; }
    }
}
