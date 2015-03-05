/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/AspNet-OpenIdConnect-Server/Owin.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.Diagnostics.CodeAnalysis;
using Microsoft.AspNet.Http;
using Microsoft.IdentityModel.Protocols;

namespace AspNet.Security.OpenIdConnect.Server {
    /// <summary>
    /// Contains data about the OpenIdConnect client redirect URI
    /// </summary>
    public sealed class OpenIdConnectValidateClientRedirectUriContext : BaseValidatingClientContext {
        /// <summary>
        /// Initializes a new instance of the <see cref="OpenIdConnectValidateClientRedirectUriContext"/> class
        /// </summary>
        /// <param name="context"></param>
        /// <param name="options"></param>
        /// <param name="authorizationRequest"></param>
        [SuppressMessage("Microsoft.Design", "CA1054:UriParametersShouldNotBeStrings",
            MessageId = "3#", Justification = "redirect_uri is a string parameter")]
        internal OpenIdConnectValidateClientRedirectUriContext(
            HttpContext context,
            OpenIdConnectServerOptions options,
            OpenIdConnectMessage authorizationRequest)
            : base(context, options, authorizationRequest) {
        }

        /// <summary>
        /// Gets the client redirect URI
        /// </summary>
        [SuppressMessage("Microsoft.Design",
            "CA1056:UriPropertiesShouldNotBeStrings",
            Justification = "redirect_uri is a string parameter")]
        public string RedirectUri {
            get { return AuthorizationRequest.RedirectUri; }
            set { AuthorizationRequest.RedirectUri = value; }
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
        [SuppressMessage("Microsoft.Design", "CA1054:UriParametersShouldNotBeStrings",
            MessageId = "0#", Justification = "redirect_uri is a string parameter")]
        public bool Validated(string redirectUri) {
            if (redirectUri == null) {
                throw new ArgumentNullException("redirectUri");
            }

            if (!string.IsNullOrEmpty(RedirectUri) && !string.Equals(RedirectUri, redirectUri, StringComparison.Ordinal)) {
                // Don't allow validation to alter redirect_uri provided with request
                return false;
            }

            RedirectUri = redirectUri;

            return Validated();
        }
    }
}
