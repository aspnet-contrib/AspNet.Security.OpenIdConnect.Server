/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.IdentityModel.Tokens.Jwt;
using AspNet.Security.OpenIdConnect.Primitives;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Tokens;

namespace AspNet.Security.OpenIdConnect.Server
{
    /// <summary>
    /// Provides context information used when receiving an identity token.
    /// </summary>
    public class DeserializeIdentityTokenContext : BaseControlContext
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="DeserializeIdentityTokenContext"/> class
        /// </summary>
        /// <param name="context"></param>
        /// <param name="options"></param>
        /// <param name="request"></param>
        /// <param name="token"></param>
        public DeserializeIdentityTokenContext(
            HttpContext context,
            OpenIdConnectServerOptions options,
            OpenIdConnectRequest request,
            string token)
            : base(context)
        {
            Options = options;
            Request = request;
            IdentityToken = token;
        }

        /// <summary>
        /// Gets the options used by the OpenID Connect server.
        /// </summary>
        public OpenIdConnectServerOptions Options { get; }

        /// <summary>
        /// Gets the OpenID Connect request.
        /// </summary>
        public new OpenIdConnectRequest Request { get; }

        /// <summary>
        /// Gets the OpenID Connect response.
        /// </summary>
        public new OpenIdConnectResponse Response
        {
            get => throw new InvalidOperationException("The OpenID Connect response is not available at this stage.");
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
