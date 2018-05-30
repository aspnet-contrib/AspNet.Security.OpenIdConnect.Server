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
    public abstract class BaseValidatingContext : HandleRequestContext<OpenIdConnectServerOptions>
    {
        /// <summary>
        /// Creates a new instance of the <see cref="BaseValidatingContext"/> class.
        /// </summary>
        protected BaseValidatingContext(
            HttpContext context,
            AuthenticationScheme scheme,
            OpenIdConnectServerOptions options,
            OpenIdConnectRequest request)
            : base(context, scheme, options)
        {
            Request = request;
        }

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
        /// Gets a boolean indicating whether the
        /// <see cref="Validate()"/> method was called.
        /// </summary>
        public bool IsValidated { get; protected set; }

        /// <summary>
        /// Gets a boolean indicating whether the
        /// <see cref="Reject()"/> method was called.
        /// </summary>
        public bool IsRejected { get; protected set; } = true;

        /// <summary>
        /// Gets or sets the "error" parameter returned to the client application.
        /// </summary>
        public string Error { get; private set; }

        /// <summary>
        /// Gets or sets the "error_description" parameter returned to the client application.
        /// </summary>
        public string ErrorDescription { get; private set; }

        /// <summary>
        /// Gets or sets the "error_uri" parameter returned to the client application.
        /// </summary>
        public string ErrorUri { get; private set; }

        /// <summary>
        /// Validates the request.
        /// </summary>
        public virtual void Validate()
        {
            Result = null;
            IsValidated = true;
            IsRejected = false;
        }

        /// <summary>
        /// Rejects the request.
        /// </summary>
        public virtual void Reject()
        {
            Result = null;
            IsRejected = true;
            IsValidated = false;
        }

        /// <summary>
        /// Rejects the request.
        /// </summary>
        /// <param name="error">The "error" parameter returned to the client application.</param>
        public virtual void Reject(string error)
        {
            Error = error;

            Reject();
        }

        /// <summary>
        /// Rejects the request.
        /// </summary>
        /// <param name="error">The "error" parameter returned to the client application.</param>
        /// <param name="description">The "error_description" parameter returned to the client application.</param>
        public virtual void Reject(string error, string description)
        {
            Error = error;
            ErrorDescription = description;

            Reject();
        }

        /// <summary>
        /// Rejects the request.
        /// </summary>
        /// <param name="error">The "error" parameter returned to the client application.</param>
        /// <param name="description">The "error_description" parameter returned to the client application.</param>
        /// <param name="uri">The "error_uri" parameter returned to the client application.</param>
        public virtual void Reject(string error, string description, string uri)
        {
            Error = error;
            ErrorDescription = description;
            ErrorUri = uri;

            Reject();
        }
    }
}
