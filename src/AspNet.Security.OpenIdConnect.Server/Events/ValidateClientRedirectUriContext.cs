/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using Microsoft.AspNet.Http;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace AspNet.Security.OpenIdConnect.Server {
    /// <summary>
    /// Contains data about the OpenIdConnect client redirect URI
    /// </summary>
    public sealed class ValidateClientRedirectUriContext : BaseValidatingClientContext {
        /// <summary>
        /// Initializes a new instance of the <see cref="ValidateClientRedirectUriContext"/> class
        /// </summary>
        /// <param name="context"></param>
        /// <param name="options"></param>
        /// <param name="request"></param>
        internal ValidateClientRedirectUriContext(
            HttpContext context,
            OpenIdConnectServerOptions options,
            OpenIdConnectMessage request)
            : base(context, options, request) {
        }

        /// <summary>
        /// Gets the client redirect URI
        /// </summary>
        public string RedirectUri {
            get { return Request.RedirectUri; }
            set { Request.RedirectUri = value; }
        }

        /// <summary>
        /// Marks this context as validated by the application.
        /// IsValidated becomes true and HasError becomes false as a result of calling.
        /// </summary>
        /// <returns></returns>
        public override bool Validated() {
            if (string.IsNullOrEmpty(RedirectUri)) {
                // Don't allow default validation when redirect_uri not provided with request
                return false;
            }

            return base.Validated();
        }

        /// <summary>
        /// Checks the redirect URI to determine whether it equals <see cref="RedirectUri"/>.
        /// </summary>
        /// <param name="redirectUri"></param>
        /// <returns></returns>
        public bool Validated(string redirectUri) {
            if (redirectUri == null) {
                throw new ArgumentNullException("redirectUri");
            }

            if (!string.IsNullOrEmpty(RedirectUri) &&
                !string.Equals(RedirectUri, redirectUri, StringComparison.Ordinal)) {
                // Don't allow validation to alter redirect_uri provided with request
                return false;
            }

            RedirectUri = redirectUri;

            return Validated();
        }

        /// <summary>
        /// Resets redirect_uri and marks the context
        /// as skipped by the application.
        /// </summary>
        public override bool Skipped() {
            // Reset redirect_uri if validation was skipped.
            RedirectUri = null;

            return base.Skipped();
        }

        /// <summary>
        /// Resets redirect_uri and marks the context
        /// as rejected by the application.
        /// </summary>
        public override bool Rejected() {
            // Reset redirect_uri if validation failed.
            RedirectUri = null;

            return base.Rejected();
        }
    }
}
