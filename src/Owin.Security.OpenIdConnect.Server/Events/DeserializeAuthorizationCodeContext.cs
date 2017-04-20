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
    /// <see cref="OpenIdConnectServerProvider.DeserializeAuthorizationCode"/> event.
    /// </summary>
    public class DeserializeAuthorizationCodeContext : BaseDeserializingContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="DeserializeAuthorizationCodeContext"/> class.
        /// </summary>
        public DeserializeAuthorizationCodeContext(
            IOwinContext context,
            OpenIdConnectServerOptions options,
            OpenIdConnectRequest request,
            string code)
            : base(context, options, request)
        {
            AuthorizationCode = code;
        }

        /// <summary>
        /// Gets or sets the data format used to deserialize the authentication ticket.
        /// </summary>
        public ISecureDataFormat<AuthenticationTicket> DataFormat { get; set; }

        /// <summary>
        /// Gets the authorization code
        /// used by the client application.
        /// </summary>
        public string AuthorizationCode { get; }
    }
}
