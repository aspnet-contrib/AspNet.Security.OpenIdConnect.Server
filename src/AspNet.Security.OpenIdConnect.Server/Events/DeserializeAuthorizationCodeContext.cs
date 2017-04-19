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
    /// <see cref="OpenIdConnectServerProvider.DeserializeAuthorizationCode"/> event.
    /// </summary>
    public class DeserializeAuthorizationCodeContext : BaseControlContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="DeserializeAuthorizationCodeContext"/> class.
        /// </summary>
        public DeserializeAuthorizationCodeContext(
            HttpContext context,
            OpenIdConnectServerOptions options,
            OpenIdConnectRequest request,
            string code)
            : base(context)
        {
            Options = options;
            Request = request;
            AuthorizationCode = code;
        }

        /// <summary>
        /// Gets the options used by the OpenID Connect server.
        /// </summary>
        public OpenIdConnectServerOptions Options { get; }

        /// <summary>
        /// Gets the OpenID Connect request.
        /// </summary>
        public new OpenIdConnectRequest Request { get; }

        /// <summary>
        /// Gets the OpenID Connect response.
        /// </summary>
        public new OpenIdConnectResponse Response
        {
            get => throw new InvalidOperationException("The OpenID Connect response is not available at this stage.");
        }

        /// <summary>
        /// Gets or sets the data format used to deserialize the authentication ticket.
        /// </summary>
        public ISecureDataFormat<AuthenticationTicket> DataFormat { get; set; }

        /// <summary>
        /// Gets the authorization code
        /// used by the client application.
        /// </summary>
        public string AuthorizationCode { get; }
    }
}
