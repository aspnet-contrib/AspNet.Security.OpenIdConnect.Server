/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using AspNet.Security.OpenIdConnect.Primitives;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Notifications;

namespace Owin.Security.OpenIdConnect.Server
{
    /// <summary>
    /// Represents the context class associated with the
    /// <see cref="OpenIdConnectServerProvider.ProcessSigninResponse"/> event.
    /// </summary>
    public class ProcessSigninResponseContext : BaseNotification<OpenIdConnectServerOptions>
    {
        /// <summary>
        /// Creates a new instance of the <see cref="ProcessSigninResponseContext"/> class.
        /// </summary>
        public ProcessSigninResponseContext(
            IOwinContext context,
            OpenIdConnectServerOptions options,
            AuthenticationTicket ticket,
            OpenIdConnectRequest request,
            OpenIdConnectResponse response)
            : base(context, options)
        {
            Ticket = ticket;
            Request = request;
            Response = response;
        }

        /// <summary>
        /// Gets the authorization or token request.
        /// </summary>
        public new OpenIdConnectRequest Request { get; }

        /// <summary>
        /// Gets the authorization or token response.
        /// </summary>
        public new OpenIdConnectResponse Response { get; }

        /// <summary>
        /// Gets the authentication ticket.
        /// </summary>
        public AuthenticationTicket Ticket { get; }

        /// <summary>
        /// Gets or sets a boolean indicating whether an access token
        /// should be returned to the client application.
        /// Note: overriding the value of this property is generally not
        /// recommended, except when dealing with non-standard clients.
        /// </summary>
        public bool IncludeAccessToken { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether an authorization code
        /// should be returned to the client application.
        /// Note: overriding the value of this property is generally not
        /// recommended, except when dealing with non-standard clients.
        /// </summary>
        public bool IncludeAuthorizationCode { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether an identity token
        /// should be returned to the client application.
        /// Note: overriding the value of this property is generally not
        /// recommended, except when dealing with non-standard clients.
        /// </summary>
        public bool IncludeIdentityToken { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether a refresh token
        /// should be returned to the client application.
        /// Note: overriding the value of this property is generally not
        /// recommended, except when dealing with non-standard clients.
        /// </summary>
        public bool IncludeRefreshToken { get; set; }
    }
}
