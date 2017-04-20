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
    /// Represents an abstract base class used for certain event contexts.
    /// </summary>
    public abstract class BaseSerializingContext : BaseContext<OpenIdConnectServerOptions>
    {
        /// <summary>
        /// Creates a new instance of the <see cref="DeserializeAccessTokenContext"/> class.
        /// </summary>
        public BaseSerializingContext(
            HttpContext context,
            AuthenticationScheme scheme,
            OpenIdConnectServerOptions options,
            OpenIdConnectRequest request,
            OpenIdConnectResponse response,
            AuthenticationTicket ticket)
            : base(context, scheme, options)
        {
            Request = request;
            Response = response;
            Ticket = ticket;
        }

        /// <summary>
        /// Gets the OpenID Connect request.
        /// </summary>
        public new OpenIdConnectRequest Request { get; }

        /// <summary>
        /// Gets the OpenID Connect response.
        /// </summary>
        public new OpenIdConnectResponse Response { get; }

        /// <summary>
        /// Gets the authentication ticket.
        /// </summary>
        public AuthenticationTicket Ticket { get; }

        /// <summary>
        /// Gets a boolean indicating whether the
        /// <see cref="HandleSerialization()"/> method was called.
        /// </summary>
        public bool IsHandled { get; private set; }

        /// <summary>
        /// Marks the serialization process as handled by the application code.
        /// </summary>
        public virtual void HandleSerialization() => IsHandled = true;
    }
}
