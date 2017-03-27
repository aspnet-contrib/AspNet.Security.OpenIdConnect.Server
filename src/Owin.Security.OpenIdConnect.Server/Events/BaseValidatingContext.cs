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
    /// Base class used for certain event contexts.
    /// </summary>
    public abstract class BaseValidatingContext : BaseNotification<OpenIdConnectServerOptions>
    {
        /// <summary>
        /// Initializes base class used for certain event contexts.
        /// </summary>
        protected BaseValidatingContext(
            IOwinContext context,
            OpenIdConnectServerOptions options,
            OpenIdConnectRequest request)
            : base(context, options)
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
            get { throw new InvalidOperationException("The OpenID Connect response is not available at this stage."); }
        }

        /// <summary>
        /// Gets whether the <see cref="Validate()"/>
        /// method has been called or not.
        /// </summary>
        public bool IsValidated { get; protected set; }

        /// <summary>
        /// Gets whether the <see cref="Reject()"/>
        /// method has been called or not.
        /// </summary>
        public bool IsRejected { get; protected set; } = true;

        /// <summary>
        /// The error argument provided when <see cref="Reject()"/> was called on this context.
        /// This is eventually returned to the client app as the OAuth2 "error" parameter.
        /// </summary>
        public string Error { get; private set; }

        /// <summary>
        /// The optional description argument provided when <see cref="Reject()"/> was called on this context.
        /// This is eventually returned to the client app as the OAuth2 "error_description" parameter.
        /// </summary>
        public string ErrorDescription { get; private set; }

        /// <summary>
        /// The optional uri argument provided when <see cref="Reject()"/> was called on this context.
        /// This is eventually returned to the client app as the OpenIdConnect "error_uri" parameter.
        /// </summary>
        public string ErrorUri { get; private set; }

        /// <summary>
        /// Marks this context as validated by the application.
        /// </summary>
        public virtual void Validate()
        {
            IsValidated = true;
            IsRejected = false;
        }

        /// <summary>
        /// Marks this context as not validated by the application.
        /// </summary>
        public virtual void Reject()
        {
            IsRejected = true;
            IsValidated = false;
        }

        /// <summary>
        /// Marks this context as not validated by the application
        /// and assigns various error information properties.
        /// </summary>
        /// <param name="error">Assigned to the <see cref="Error"/> property.</param>
        public virtual void Reject(string error)
        {
            Error = error;

            Reject();
        }

        /// <summary>
        /// Marks this context as not validated by the application
        /// and assigns various error information properties.
        /// </summary>
        /// <param name="error">Assigned to the <see cref="Error"/> property.</param>
        /// <param name="description">Assigned to the <see cref="ErrorDescription"/> property.</param>
        public virtual void Reject(string error, string description)
        {
            Error = error;
            ErrorDescription = description;

            Reject();
        }

        /// <summary>
        /// Marks this context as not validated by the application
        /// and assigns various error information properties.
        /// </summary>
        /// <param name="error">Assigned to the <see cref="Error"/> property</param>
        /// <param name="description">Assigned to the <see cref="ErrorDescription"/> property</param>
        /// <param name="uri">Assigned to the <see cref="ErrorUri"/> property</param>
        public virtual void Reject(string error, string description, string uri)
        {
            Error = error;
            ErrorDescription = description;
            ErrorUri = uri;

            Reject();
        }
    }
}
