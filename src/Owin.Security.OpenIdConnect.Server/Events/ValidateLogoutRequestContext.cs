/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using Microsoft.IdentityModel.Protocols;
using Microsoft.Owin;

namespace Owin.Security.OpenIdConnect.Server {
    /// <summary>
    /// Provides context information used when validating a logout request.
    /// </summary>
    public class ValidateLogoutRequestContext : BaseValidatingContext {
        /// <summary>
        /// Initializes a new instance of the <see cref="ValidateLogoutRequestContext"/> class.
        /// </summary>
        /// <param name="context"></param>
        /// <param name="options"></param>
        /// <param name="request"></param>
        public ValidateLogoutRequestContext(
            IOwinContext context,
            OpenIdConnectServerOptions options,
            OpenIdConnectMessage request)
            : base(context, options) {
            Request = request;

            // Note: if the optional post_logout_redirect_uri parameter
            // is missing, mark the validation context as skipped.
            // See http://openid.net/specs/openid-connect-session-1_0.html#RPLogout
            if (string.IsNullOrEmpty(request.PostLogoutRedirectUri)) {
                Skip();
            }
        }

        /// <summary>
        /// Gets the authorization request.
        /// </summary>
        public new OpenIdConnectMessage Request { get; }

        /// <summary>
        /// Gets the post logout redirect URI.
        /// </summary>
        public string PostLogoutRedirectUri {
            get { return Request.PostLogoutRedirectUri; }
            set { Request.PostLogoutRedirectUri = value; }
        }

        /// <summary>
        /// Marks this context as validated by the application.
        /// IsValidated becomes true and HasError becomes false as a result of calling.
        /// </summary>
        /// <returns></returns>
        public override bool Validate() {
            if (string.IsNullOrEmpty(PostLogoutRedirectUri)) {
                // Don't allow default validation when
                // redirect_uri not provided with request.
                return false;
            }

            return base.Validate();
        }

        /// <summary>
        /// Checks the redirect URI to determine whether it equals <see cref="PostLogoutRedirectUri"/>.
        /// </summary>
        /// <param name="redirectUri"></param>
        /// <returns></returns>
        public bool Validate(string redirectUri) {
            if (redirectUri == null) {
                throw new ArgumentNullException("redirectUri");
            }

            if (!string.IsNullOrEmpty(PostLogoutRedirectUri) &&
                !string.Equals(PostLogoutRedirectUri, redirectUri, StringComparison.Ordinal)) {
                // Don't allow validation to alter redirect_uri provided with request
                return false;
            }

            PostLogoutRedirectUri = redirectUri;

            return Validate();
        }

        /// <summary>
        /// Resets post_logout_redirect_uri and marks
        /// the context as skipped by the application.
        /// </summary>
        public override bool Skip() {
            // Reset post_logout_redirect_uri if validation was skipped.
            PostLogoutRedirectUri = null;

            return base.Skip();
        }

        /// <summary>
        /// Resets post_logout_redirect_uri and marks
        /// the context as rejected by the application.
        /// </summary>
        public override bool Reject() {
            // Reset post_logout_redirect_uri if validation failed.
            PostLogoutRedirectUri = null;

            return base.Reject();
        }
    }
}
