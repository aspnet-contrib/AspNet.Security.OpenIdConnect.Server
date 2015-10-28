/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using Microsoft.AspNet.Authentication;
using Microsoft.AspNet.Http;

namespace AspNet.Security.OpenIdConnect.Server {
    /// <summary>
    /// Base class used for certain event contexts.
    /// </summary>
    public abstract class BaseValidatingContext : BaseControlContext {
        /// <summary>
        /// Initializes base class used for certain event contexts.
        /// </summary>
        protected BaseValidatingContext(
            HttpContext context,
            OpenIdConnectServerOptions options)
            : base(context) {
            Options = options;
        }

        /// <summary>
        /// Gets the options used by the OpenID Connect server.
        /// </summary>
        public OpenIdConnectServerOptions Options { get; }

        /// <summary>
        /// Gets whether the <see cref="Skipped"/>
        /// method has been called or not.
        /// </summary>
        public bool IsSkipped { get; private set; }

        /// <summary>
        /// Gets whether the <see cref="Validated"/>
        /// method has been called or not.
        /// </summary>
        public bool IsValidated { get; private set; }

        /// <summary>
        /// Gets whether the <see cref="Rejected"/>
        /// method has been called or not.
        /// </summary>
        public bool IsRejected { get; private set; } = true;

        /// <summary>
        /// The error argument provided when <see cref="Rejected"/> was called on this context.
        /// This is eventually returned to the client app as the OAuth2 "error" parameter.
        /// </summary>
        public string Error { get; private set; }

        /// <summary>
        /// The optional description argument provided when <see cref="Rejected"/> was called on this context.
        /// This is eventually returned to the client app as the OAuth2 "error_description" parameter.
        /// </summary>
        public string ErrorDescription { get; private set; }

        /// <summary>
        /// The optional uri argument provided when <see cref="Rejected"/> was called on this context.
        /// This is eventually returned to the client app as the OpenIdConnect "error_uri" parameter.
        /// </summary>
        public string ErrorUri { get; private set; }

        /// <summary>
        /// Marks the context as skipped by the application.
        /// </summary>
        /// <returns></returns>
        public virtual new bool Skipped() {
            IsSkipped = true;
            IsRejected = false;
            IsValidated = false;

            return true;
        }

        /// <summary>
        /// Marks this context as validated by the application.
        /// </summary>
        /// <returns>True if the validation has taken effect.</returns>
        public virtual bool Validated() {
            IsSkipped = false;
            IsValidated = true;
            IsRejected = false;

            return true;
        }

        /// <summary>
        /// Marks this context as not validated by the application.
        /// </summary>
        public virtual bool Rejected() {
            IsSkipped = false;
            IsRejected = true;
            IsValidated = false;

            return true;
        }

        /// <summary>
        /// Marks this context as not validated by the application
        /// and assigns various error information properties.
        /// </summary>
        /// <param name="error">Assigned to the <see cref="Error"/> property.</param>
        public virtual bool Rejected(string error) {
            Error = error;

            return Rejected();
        }

        /// <summary>
        /// Marks this context as not validated by the application
        /// and assigns various error information properties.
        /// </summary>
        /// <param name="error">Assigned to the <see cref="Error"/> property.</param>
        /// <param name="description">Assigned to the <see cref="ErrorDescription"/> property.</param>
        public virtual bool Rejected(string error, string description) {
            Error = error;
            ErrorDescription = description;

            return Rejected();
        }

        /// <summary>
        /// Marks this context as not validated by the application
        /// and assigns various error information properties.
        /// </summary>
        /// <param name="error">Assigned to the <see cref="Error"/> property</param>
        /// <param name="description">Assigned to the <see cref="ErrorDescription"/> property</param>
        /// <param name="uri">Assigned to the <see cref="ErrorUri"/> property</param>
        public virtual bool Rejected(string error, string description, string uri) {
            Error = error;
            ErrorDescription = description;
            ErrorUri = uri;

            return Rejected();
        }
    }
}
