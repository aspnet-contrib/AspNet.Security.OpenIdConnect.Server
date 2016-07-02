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
    /// Provides context information used when validating an authorization request.
    /// </summary>
    public class ValidateAuthorizationRequestContext : BaseValidatingContext {
        /// <summary>
        /// Initializes a new instance of the <see cref="ValidateAuthorizationRequestContext"/> class.
        /// </summary>
        /// <param name="context"></param>
        /// <param name="options"></param>
        /// <param name="request"></param>
        public ValidateAuthorizationRequestContext(
            IOwinContext context,
            OpenIdConnectServerOptions options,
            OpenIdConnectMessage request)
            : base(context, options) {
            Request = request;
        }

        /// <summary>
        /// Gets the authorization request.
        /// </summary>
        public new OpenIdConnectMessage Request { get; }

        /// <summary>
        /// Gets the client identifier.
        /// </summary>
        public string ClientId => Request.ClientId;

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
        public override bool Validate() {
            if (string.IsNullOrEmpty(RedirectUri)) {
                // Don't allow default validation when
                // the redirect_uri is not provided.
                return false;
            }

            return base.Validate();
        }

        /// <summary>
        /// Checks the redirect URI to determine whether it equals <see cref="RedirectUri"/>.
        /// </summary>
        /// <param name="address"></param>
        /// <returns></returns>
        public bool Validate(string address) {
            if (string.IsNullOrEmpty(address)) {
                throw new ArgumentException("The redirect_uri cannot be null or empty.", nameof(address));
            }

            if (!string.IsNullOrEmpty(RedirectUri) &&
                !string.Equals(RedirectUri, address, StringComparison.Ordinal)) {
                // Don't allow validation to alter the redirect_uri
                // parameter extracted from the request.
                return false;
            }

            RedirectUri = address;

            return Validate();
        }
    }
}
