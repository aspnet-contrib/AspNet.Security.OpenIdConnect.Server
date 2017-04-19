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
    /// Represents the context class associated with the
    /// <see cref="OpenIdConnectServerProvider.ValidateAuthorizationRequest"/> event.
    /// </summary>
    public class ValidateAuthorizationRequestContext : BaseValidatingContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="ValidateAuthorizationRequestContext"/> class.
        /// </summary>
        public ValidateAuthorizationRequestContext(
            IOwinContext context,
            OpenIdConnectServerOptions options,
            OpenIdConnectRequest request)
            : base(context, options, request)
        {
            RedirectUri = request.RedirectUri;
        }

        /// <summary>
        /// Gets the client_id specified by the client application.
        /// </summary>
        public string ClientId => Request.ClientId;

        /// <summary>
        /// Gets the redirect_uri specified by the client application.
        /// If it's not provided by the client, it must be set by
        /// the user code by calling <see cref="Validate(string)"/>.
        /// </summary>
        public string RedirectUri { get; private set; }

        /// <summary>
        /// Marks this context as validated by the application.
        /// IsValidated becomes true and HasError becomes false as a result of calling.
        /// </summary>>
        public override void Validate()
        {
            // Don't allow default validation when the redirect_uri
            // is not explicitly provided by the client application.
            if (string.IsNullOrEmpty(Request.RedirectUri))
            {
                throw new InvalidOperationException(
                    "The authorization request cannot be validated because no " +
                    "redirect_uri was specified by the client application.");
            }

            base.Validate();
        }

        /// <summary>
        /// Checks the redirect URI to determine whether it equals <see cref="RedirectUri"/>.
        /// </summary>
        /// <param name="address"></param>
        public void Validate(string address)
        {
            if (string.IsNullOrEmpty(address))
            {
                throw new ArgumentException("The redirect_uri cannot be null or empty.", nameof(address));
            }

            // Don't allow validation to alter the redirect_uri parameter extracted
            // from the request if the address was explicitly provided by the client.
            if (!string.IsNullOrEmpty(Request.RedirectUri) &&
                !string.Equals(Request.RedirectUri, address, StringComparison.Ordinal))
            {
                throw new InvalidOperationException(
                    "The authorization request cannot be validated because a different " +
                    "redirect_uri was specified by the client application.");
            }

            RedirectUri = address;

            base.Validate();
        }
    }
}
