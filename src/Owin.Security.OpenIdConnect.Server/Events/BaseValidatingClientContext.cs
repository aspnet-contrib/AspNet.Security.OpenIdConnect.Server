/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using AspNet.Security.OpenIdConnect.Primitives;
using Microsoft.Owin;

namespace Owin.Security.OpenIdConnect.Server
{
    /// <summary>
    /// Base class used for certain event contexts
    /// </summary>
    public abstract class BaseValidatingClientContext : BaseValidatingContext
    {
        /// <summary>
        /// Initializes base class used for certain event contexts
        /// </summary>
        protected BaseValidatingClientContext(
            IOwinContext context,
            OpenIdConnectServerOptions options,
            OpenIdConnectRequest request)
            : base(context, options, request)
        {
            ClientId = request.ClientId;
        }

        /// <summary>
        /// The "client_id" parameter for the current request.
        /// The authorization server application is responsible for
        /// validating this value to ensure it identifies a registered client.
        /// </summary>
        public string ClientId { get; private set; }

        /// <summary>
        /// The "client_secret" parameter for the current request.
        /// The authorization server application is responsible for
        /// validating this value to ensure it identifies a registered client.
        /// </summary>
        public string ClientSecret => Request.ClientSecret;

        /// <summary>
        /// Marks this context as validated by the application.
        /// IsValidated becomes true and HasError becomes false as a result of calling.
        /// </summary>>
        public override void Validate()
        {
            // Don't allow default validation when the client_id
            // is not explicitly provided by the client application.
            if (string.IsNullOrEmpty(Request.ClientId))
            {
                throw new InvalidOperationException(
                    "The request cannot be validated because no " +
                    "client_id was specified by the client application.");
            }

            base.Validate();
        }

        /// <summary>
        /// Sets client_id and marks the context
        /// as validated by the application.
        /// </summary>
        /// <param name="identifier"></param>
        public void Validate(string identifier)
        {
            if (string.IsNullOrEmpty(identifier))
            {
                throw new ArgumentException("The client_id cannot be null or empty.", nameof(identifier));
            }

            // Don't allow validation to alter the client_id parameter extracted
            // from the request if the address was explicitly provided by the client.
            if (!string.IsNullOrEmpty(Request.ClientId) &&
                !string.Equals(Request.ClientId, identifier, StringComparison.Ordinal))
            {
                throw new InvalidOperationException(
                    "The request cannot be validated because a different " +
                    "client_id was specified by the client application.");
            }

            ClientId = identifier;

            base.Validate();
        }
    }
}
