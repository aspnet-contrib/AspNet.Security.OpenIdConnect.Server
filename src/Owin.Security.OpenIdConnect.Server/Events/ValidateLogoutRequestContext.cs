/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using AspNet.Security.OpenIdConnect.Primitives;
using Microsoft.Owin;

namespace Owin.Security.OpenIdConnect.Server
{
    /// <summary>
    /// Provides context information used when validating a logout request.
    /// </summary>
    public class ValidateLogoutRequestContext : BaseValidatingContext
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="ValidateLogoutRequestContext"/> class.
        /// </summary>
        /// <param name="context"></param>
        /// <param name="options"></param>
        /// <param name="request"></param>
        public ValidateLogoutRequestContext(
            IOwinContext context,
            OpenIdConnectServerOptions options,
            OpenIdConnectRequest request)
            : base(context, options, request)
        {
            // Note: if the optional post_logout_redirect_uri parameter
            // is missing, mark the validation context as skipped.
            // See http://openid.net/specs/openid-connect-session-1_0.html#RPLogout
            if (string.IsNullOrEmpty(request.PostLogoutRedirectUri))
            {
                Skip();
            }
        }

        /// <summary>
        /// Gets the post logout redirect URI.
        /// </summary>
        public string PostLogoutRedirectUri
        {
            get { return Request.PostLogoutRedirectUri; }
            set { Request.PostLogoutRedirectUri = value; }
        }

        /// <summary>
        /// Marks this context as validated by the application.
        /// IsValidated becomes true and HasError becomes false as a result of calling.
        /// </summary>
        /// <returns></returns>
        public override bool Validate()
        {
            if (string.IsNullOrEmpty(PostLogoutRedirectUri))
            {
                // Don't allow default validation when
                // the redirect_uri is not provided.
                return false;
            }

            return base.Validate();
        }

        /// <summary>
        /// Checks the redirect URI to determine whether it equals <see cref="PostLogoutRedirectUri"/>.
        /// </summary>
        /// <param name="address"></param>
        /// <returns></returns>
        public bool Validate(string address)
        {
            if (string.IsNullOrEmpty(address))
            {
                throw new ArgumentException("The post_logout_redirect_uri cannot be null or empty.", nameof(address));
            }

            if (!string.IsNullOrEmpty(PostLogoutRedirectUri) &&
                !string.Equals(PostLogoutRedirectUri, address, StringComparison.Ordinal))
            {
                // Don't allow validation to alter the redirect_uri
                // parameter extracted from the request.
                return false;
            }

            PostLogoutRedirectUri = address;

            return Validate();
        }
    }
}
