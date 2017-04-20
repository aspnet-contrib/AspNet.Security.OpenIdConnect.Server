/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using AspNet.Security.OpenIdConnect.Primitives;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace AspNet.Security.OpenIdConnect.Server
{
    /// <summary>
    /// Represents the context class associated with the
    /// <see cref="OpenIdConnectServerProvider.DeserializeRefreshToken"/> event.
    /// </summary>
    public class DeserializeRefreshTokenContext : BaseDeserializingContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="DeserializeRefreshTokenContext"/> class.
        /// </summary>
        public DeserializeRefreshTokenContext(
            HttpContext context,
            AuthenticationScheme scheme,
            OpenIdConnectServerOptions options,
            OpenIdConnectRequest request,
            string token)
            : base(context, scheme, options, request)
        {
            RefreshToken = token;
        }

        /// <summary>
        /// Gets or sets the data format used to deserialize the authentication ticket.
        /// </summary>
        public ISecureDataFormat<AuthenticationTicket> DataFormat { get; set; }

        /// <summary>
        /// Gets the refresh token used by the client application.
        /// </summary>
        public string RefreshToken { get; }
    }
}
