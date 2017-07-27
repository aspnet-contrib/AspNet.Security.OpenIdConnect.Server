/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System.IdentityModel.Tokens.Jwt;
using AspNet.Security.OpenIdConnect.Primitives;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Owin;

namespace Owin.Security.OpenIdConnect.Server
{
    /// <summary>
    /// Represents the context class associated with the
    /// <see cref="OpenIdConnectServerProvider.DeserializeIdentityToken"/> event.
    /// </summary>
    public class DeserializeIdentityTokenContext : BaseDeserializingContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="DeserializeIdentityTokenContext"/> class.
        /// </summary>
        public DeserializeIdentityTokenContext(
            IOwinContext context,
            OpenIdConnectServerOptions options,
            OpenIdConnectRequest request,
            string token)
            : base(context, options, request)
        {
            IdentityToken = token;
        }

        /// <summary>
        /// Gets or sets the validation parameters used to verify the authenticity of identity tokens.
        /// </summary>
        public TokenValidationParameters TokenValidationParameters { get; set; } = new TokenValidationParameters();

        /// <summary>
        /// Gets or sets the security token handler used to
        /// deserialize the authentication ticket.
        /// </summary>
        public JwtSecurityTokenHandler SecurityTokenHandler { get; set; }

        /// <summary>
        /// Gets the identity token used by the client application.
        /// </summary>
        public string IdentityToken { get; }
    }
}
