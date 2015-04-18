/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.Diagnostics.CodeAnalysis;
using Microsoft.AspNet.Http;
using Microsoft.IdentityModel.Protocols;

namespace AspNet.Security.OpenIdConnect.Server {
    /// <summary>
    /// Contains data about the OpenIdConnect client logout redirect URI
    /// </summary>
    public sealed class ValidateClientLogoutRedirectUriNotification : BaseValidatingClientNotification {
        /// <summary>
        /// Initializes a new instance of the <see cref="ValidateClientLogoutRedirectUriNotification"/> class
        /// </summary>
        /// <param name="context"></param>
        /// <param name="options"></param>
        /// <param name="request"></param>
        [SuppressMessage("Microsoft.Design", "CA1054:UriParametersShouldNotBeStrings",
            MessageId = "3#", Justification = "redirect_uri is a string parameter")]
        internal ValidateClientLogoutRedirectUriNotification(
            HttpContext context,
            OpenIdConnectServerOptions options,
            OpenIdConnectMessage request)
            : base(context, options, request) {
        }

        /// <summary>
        /// Gets the post logout redirect URI.
        /// </summary>
        public string PostLogoutRedirectUri {
            get { return AuthorizationRequest.PostLogoutRedirectUri; }
            set { AuthorizationRequest.PostLogoutRedirectUri = value; }
        }

        /// <summary>
        /// Marks this context as validated by the application.
        /// IsValidated becomes true and HasError becomes false as a result of calling.
        /// </summary>
        /// <returns></returns>
        public override bool Validated() {
            if (string.IsNullOrEmpty(PostLogoutRedirectUri)) {
                // Don't allow default validation when redirect_uri not provided with request
                return false;
            }

            return base.Validated();
        }

        /// <summary>
        /// Checks the redirect URI to determine whether it equals <see cref="PostLogoutRedirectUri"/>.
        /// </summary>
        /// <param name="redirectUri"></param>
        /// <returns></returns>
        [SuppressMessage("Microsoft.Design", "CA1054:UriParametersShouldNotBeStrings",
            MessageId = "0#", Justification = "redirect_uri is a string parameter")]
        public bool Validated(string redirectUri) {
            if (redirectUri == null) {
                throw new ArgumentNullException("redirectUri");
            }

            if (!string.IsNullOrEmpty(PostLogoutRedirectUri) && !string.Equals(PostLogoutRedirectUri, redirectUri, StringComparison.Ordinal)) {
                // Don't allow validation to alter redirect_uri provided with request
                return false;
            }

            PostLogoutRedirectUri = redirectUri;

            return Validated();
        }
    }
}
