/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using AspNet.Security.OpenIdConnect.Primitives;
using Microsoft.Owin;
using Microsoft.Owin.Security.Notifications;

namespace Owin.Security.OpenIdConnect.Server
{
    /// <summary>
    /// Represents the context class associated with the
    /// <see cref="OpenIdConnectServerProvider.ApplyUserinfoResponse"/> event.
    /// </summary>
    public class ApplyUserinfoResponseContext : BaseNotification<OpenIdConnectServerOptions>
    {
        /// <summary>
        /// Creates a new instance of the <see cref="ApplyUserinfoResponseContext"/> class.
        /// </summary>
        public ApplyUserinfoResponseContext(
            IOwinContext context,
            OpenIdConnectServerOptions options,
            OpenIdConnectRequest request,
            OpenIdConnectResponse response)
            : base(context, options)
        {
            Request = request;
            Response = response;
        }

        /// <summary>
        /// Gets the userinfo request.
        /// </summary>
        /// <remarks>
        /// Note: this property may be null if an error occurred while
        /// extracting the userinfo request from the HTTP request.
        /// </remarks>
        public new OpenIdConnectRequest Request { get; }

        /// <summary>
        /// Gets the userinfo response.
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
