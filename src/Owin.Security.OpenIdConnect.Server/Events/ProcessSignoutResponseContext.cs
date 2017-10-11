/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using AspNet.Security.OpenIdConnect.Primitives;
using Microsoft.Owin;
using Microsoft.Owin.Security;

namespace Owin.Security.OpenIdConnect.Server
{
    /// <summary>
    /// Represents the context class associated with the
    /// <see cref="OpenIdConnectServerProvider.ProcessSignoutResponse"/> event.
    /// </summary>
    public class ProcessSignoutResponseContext : BaseValidatingContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="ProcessSignoutResponseContext"/> class.
        /// </summary>
        public ProcessSignoutResponseContext(
            IOwinContext context,
            OpenIdConnectServerOptions options,
            AuthenticationProperties properties,
            OpenIdConnectRequest request,
            OpenIdConnectResponse response)
            : base(context, options, request)
        {
            Validate();
            Properties = properties;
            Response = response;
        }

        /// <summary>
        /// Gets the OpenID Connect response.
        /// </summary>
        public new OpenIdConnectResponse Response { get; }

        /// <summary>
        /// Gets or sets the authentication properties.
        /// </summary>
        public AuthenticationProperties Properties { get; set; }
    }
}
