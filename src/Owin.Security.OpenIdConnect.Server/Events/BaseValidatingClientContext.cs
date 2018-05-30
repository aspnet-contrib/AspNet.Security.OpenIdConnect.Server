/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using AspNet.Security.OpenIdConnect.Primitives;
using Microsoft.Owin;
using Microsoft.Owin.Security.Notifications;

namespace Owin.Security.OpenIdConnect.Server
{
    /// <summary>
    /// Represents an abstract base class used for certain event contexts.
    /// </summary>
    public abstract class BaseValidatingClientContext : BaseValidatingContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="BaseValidatingClientContext"/> class.
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
        /// Gets the "client_id" parameter for the current request.
        /// The authorization server application is responsible for
        /// validating this value to ensure it identifies a registered client.
        /// </summary>
        public string ClientId { get; private set; }

        /// <summary>
        /// Gets the "client_secret" parameter for the current request.
        /// The authorization server application is responsible for
        /// validating this value to ensure it identifies a registered client.
        /// </summary>
        public string ClientSecret => Request.ClientSecret;

        /// <summary>
        /// Gets a boolean indicating whether the
        /// <see cref="Skip()"/> method was called.
        /// </summary>
        public bool IsSkipped { get; private set; }

        /// <summary>
        /// Skips the request validation.
        /// </summary>
        public virtual void Skip()
        {
            State = NotificationResultState.Continue;
            IsSkipped = true;
            IsRejected = false;
            IsValidated = false;
        }

        /// <summary>
        /// Rejects the request.
        /// </summary>
        public override void Reject()
        {
            State = NotificationResultState.Continue;
            IsSkipped = false;
            IsRejected = true;
            IsValidated = false;
        }

        /// <summary>
        /// Validates the request.
        /// </summary>
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

            IsSkipped = false;

            base.Validate();
        }

        /// <summary>
        /// Validates the request and uses the specified identifier as the client identifier.
        /// </summary>
        /// <param name="identifier">The "client_id" validated by the user code.</param>
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
            IsSkipped = false;

            base.Validate();
        }
    }
}
