/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System.Diagnostics.CodeAnalysis;
using Microsoft.AspNet.Authentication.Notifications;
using Microsoft.AspNet.Http;

namespace AspNet.Security.OpenIdConnect.Server {
    /// <summary>
    /// Base class used for certain event contexts
    /// </summary>
    public abstract class BaseValidatingNotification<TOptions> : BaseNotification<TOptions> {
        /// <summary>
        /// Initializes base class used for certain event contexts
        /// </summary>
        protected BaseValidatingNotification(
            HttpContext context,
            TOptions options)
            : base(context, options) {
        }

        /// <summary>
        /// True if application code has called any of the Validate methods on this context.
        /// </summary>
        public bool IsValidated { get; private set; }

        /// <summary>
        /// True if application code has called any of the SetError methods on this context.
        /// </summary>
        public bool HasError { get; private set; }

        /// <summary>
        /// The error argument provided when SetError was called on this context. This is eventually
        /// returned to the client app as the OpenIdConnect "error" parameter.
        /// </summary>
        public string Error { get; private set; }

        /// <summary>
        /// The optional errorDescription argument provided when SetError was called on this context. This is eventually
        /// returned to the client app as the OpenIdConnect "error_description" parameter.
        /// </summary>
        public string ErrorDescription { get; private set; }

        /// <summary>
        /// The optional errorUri argument provided when SetError was called on this context. This is eventually
        /// returned to the client app as the OpenIdConnect "error_uri" parameter.
        /// </summary>
        [SuppressMessage("Microsoft.Design", "CA1056:UriPropertiesShouldNotBeStrings",
            Justification = "error_uri is a string value in the protocol")]
        public string ErrorUri { get; private set; }

        /// <summary>
        /// Marks this context as validated by the application. IsValidated becomes true and HasError becomes false as a result of calling.
        /// </summary>
        /// <returns>True if the validation has taken effect.</returns>
        public virtual bool Validated() {
            IsValidated = true;
            HasError = false;
            return true;
        }

        /// <summary>
        /// Marks this context as not validated by the application. IsValidated and HasError become false as a result of calling.
        /// </summary>
        public virtual void Rejected() {
            IsValidated = false;
            HasError = false;
        }

        /// <summary>
        /// Marks this context as not validated by the application and assigns various error information properties. 
        /// HasError becomes true and IsValidated becomes false as a result of calling.
        /// </summary>
        /// <param name="error">Assigned to the Error property</param>
        public void SetError(string error) {
            SetError(error, null);
        }

        /// <summary>
        /// Marks this context as not validated by the application and assigns various error information properties. 
        /// HasError becomes true and IsValidated becomes false as a result of calling.
        /// </summary>
        /// <param name="error">Assigned to the Error property</param>
        /// <param name="errorDescription">Assigned to the ErrorDescription property</param>
        public void SetError(string error,
            string errorDescription) {
            SetError(error, errorDescription, null);
        }

        /// <summary>
        /// Marks this context as not validated by the application and assigns various error information properties. 
        /// HasError becomes true and IsValidated becomes false as a result of calling.
        /// </summary>
        /// <param name="error">Assigned to the Error property</param>
        /// <param name="errorDescription">Assigned to the ErrorDescription property</param>
        /// <param name="errorUri">Assigned to the ErrorUri property</param>
        [SuppressMessage("Microsoft.Design", "CA1054:UriParametersShouldNotBeStrings",
            MessageId = "2#", Justification = "error_uri is a string value in the protocol")]
        public void SetError(string error,
            string errorDescription,
            string errorUri) {
            Error = error;
            ErrorDescription = errorDescription;
            ErrorUri = errorUri;
            Rejected();
            HasError = true;
        }
    }
}
