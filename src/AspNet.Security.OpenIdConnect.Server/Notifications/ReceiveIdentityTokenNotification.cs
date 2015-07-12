/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System.IdentityModel.Tokens;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNet.Authentication;
using Microsoft.AspNet.Authentication.Notifications;
using Microsoft.AspNet.Http;
using Microsoft.AspNet.Http.Authentication;
using Microsoft.IdentityModel.Protocols;

namespace AspNet.Security.OpenIdConnect.Server {
    /// <summary>
    /// Provides context information used when receiving an identity token.
    /// </summary>
    public sealed class ReceiveIdentityTokenNotification : BaseNotification<OpenIdConnectServerOptions> {
        /// <summary>
        /// Initializes a new instance of the <see cref="ReceiveAccessTokenNotification"/> class
        /// </summary>
        /// <param name="context"></param>
        /// <param name="options"></param>
        /// <param name="request"></param>
        /// <param name="token"></param>
        internal ReceiveIdentityTokenNotification(
            HttpContext context,
            OpenIdConnectServerOptions options,
            OpenIdConnectMessage request,
            string token)
            : base(context, options) {
            Request = request;
            IdentityToken = token;
        }

        /// <summary>
        /// Gets the authorization or token request.
        /// </summary>
        public new OpenIdConnectMessage Request { get; }

        /// <summary>
        /// Gets or sets the issuer address.
        /// </summary>
        public string Issuer { get; set; }

        /// <summary>
        /// Gets or sets the signature provider used to
        /// verify the authenticity of the identity token.
        /// </summary>
        public SignatureProvider SignatureProvider { get; set; }

        /// <summary>
        /// Gets or sets the signing credentials used to
        /// verify the authenticity of the identity token.
        /// </summary>
        public SigningCredentials SigningCredentials { get; set; }

        /// <summary>
        /// Gets or sets the security token handler used to
        /// deserialize the authentication ticket.
        /// </summary>
        public JwtSecurityTokenHandler SecurityTokenHandler { get; set; }

        /// <summary>
        /// Gets the identity token used by the client application.
        /// </summary>
        public string IdentityToken { get; }

        /// <summary>
        /// Deserialize and unprotect the authentication ticket.
        /// </summary>
        /// <returns>The authentication ticket.</returns>
        public Task<AuthenticationTicket> DeserializeTicketAsync() => DeserializeTicketAsync(IdentityToken);

        /// <summary>
        /// Deserialize and verify the authentication ticket.
        /// </summary>
        /// <param name="ticket">The serialized ticket.</param>
        /// <returns>The authentication ticket.</returns>
        public Task<AuthenticationTicket> DeserializeTicketAsync(string ticket) {
            if (SecurityTokenHandler == null) {
                return Task.FromResult<AuthenticationTicket>(null);
            }

            // Create new validation parameters to validate the security token.
            // ValidateAudience and ValidateLifetime are always set to false:
            // if necessary, the audience and the expiration can be validated
            // in InvokeValidationEndpointAsync or InvokeTokenEndpointAsync.
            var parameters = new TokenValidationParameters {
                IssuerSigningKey = SigningCredentials.SigningKey,
                ValidIssuer = Issuer,
                ValidateAudience = false,
                ValidateLifetime = false
            };

            SecurityToken token;
            var principal = SecurityTokenHandler.ValidateToken(ticket, parameters, out token);

            // Parameters stored in AuthenticationProperties are lost
            // when the identity token is serialized using a security token handler.
            // To mitigate that, they are inferred from the claims or the security token.
            var properties = new AuthenticationProperties {
                ExpiresUtc = token.ValidTo,
                IssuedUtc = token.ValidFrom
            };

            var audiences = principal.FindAll(JwtRegisteredClaimNames.Aud);
            if (audiences.Any()) {
                properties.SetAudiences(audiences.Select(claim => claim.Value));
            }

            return Task.FromResult(new AuthenticationTicket(principal, properties, Options.AuthenticationScheme));
        }
    }
}
