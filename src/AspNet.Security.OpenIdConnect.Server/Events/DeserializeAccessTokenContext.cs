/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using Microsoft.AspNet.Authentication;
using Microsoft.AspNet.Http;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace AspNet.Security.OpenIdConnect.Server {
    /// <summary>
    /// Provides context information used when receiving an access token.
    /// </summary>
    public sealed class DeserializeAccessTokenContext : BaseContext {
        /// <summary>
        /// Initializes a new instance of the <see cref="DeserializeAccessTokenContext"/> class
        /// </summary>
        /// <param name="context"></param>
        /// <param name="options"></param>
        /// <param name="request"></param>
        /// <param name="token"></param>
        internal DeserializeAccessTokenContext(
            HttpContext context,
            OpenIdConnectServerOptions options,
            OpenIdConnectMessage request,
            string token)
            : base(context) {
            Options = options;
            Request = request;
            AccessToken = token;
        }

        /// <summary>
        /// Gets or sets the deserialized authentication ticket.
        /// </summary>
        public AuthenticationTicket AuthenticationTicket { get; set; }

        /// <summary>
        /// Gets the options used by the OpenID Connect server.
        /// </summary>
        public OpenIdConnectServerOptions Options { get; }

        /// <summary>
        /// Gets the authorization or token request.
        /// </summary>
        public new OpenIdConnectMessage Request { get; }

        /// <summary>
        /// Gets or sets the issuer address.
        /// </summary>
        public string Issuer { get; set; }

        /// <summary>
        /// Gets or sets the signing credentials used to
        /// verify the authenticity of the access token.
        /// </summary>
        public SigningCredentials SigningCredentials { get; set; }

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
