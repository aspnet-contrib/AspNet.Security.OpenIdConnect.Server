/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using AspNet.Security.OpenIdConnect.Primitives;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Owin;
using Microsoft.Owin.Security;

namespace Owin.Security.OpenIdConnect.Server
{
    /// <summary>
    /// Represents the context class associated with the
    /// <see cref="OpenIdConnectServerProvider.DeserializeAccessToken"/> event.
    /// </summary>
    public class DeserializeAccessTokenContext : BaseDeserializingContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="DeserializeAccessTokenContext"/> class.
        /// </summary>
        public DeserializeAccessTokenContext(
            IOwinContext context,
            OpenIdConnectServerOptions options,
            OpenIdConnectRequest request,
            string token)
            : base(context, options, request)
        {
            AccessToken = token;
        }

        /// <summary>
        /// Gets or sets the validation parameters used to verify the authenticity of access tokens.
        /// Note: this property is only used when <see cref="SecurityTokenHandler"/> is not <c>null</c>.
        /// </summary>
        public TokenValidationParameters TokenValidationParameters { get; set; } = new TokenValidationParameters();

        /// <summary>
        /// Gets or sets the data format used to deserialize the authentication ticket.
        /// Note: this property is only used when <see cref="SecurityTokenHandler"/> is <c>null</c>.
        /// </summary>
        public ISecureDataFormat<AuthenticationTicket> DataFormat { get; set; }

        /// <summary>
        /// Gets or sets the security token handler used to
        /// deserialize the authentication ticket.
        /// </summary>
        public SecurityTokenHandler SecurityTokenHandler { get; set; }

        /// <summary>
        /// Gets the access token used by the client application.
        /// </summary>
        public string AccessToken { get; }
    }
}
