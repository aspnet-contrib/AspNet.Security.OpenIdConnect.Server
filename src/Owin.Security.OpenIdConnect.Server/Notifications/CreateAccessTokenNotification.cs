/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System.Collections.Generic;
using System.IdentityModel.Protocols.WSTrust;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Protocols;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Notifications;

namespace Owin.Security.OpenIdConnect.Server {
    /// <summary>
    /// Provides context information used when issuing an access token.
    /// </summary>
    public sealed class CreateAccessTokenNotification : BaseNotification<OpenIdConnectServerOptions> {
        /// <summary>
        /// Initializes a new instance of the <see cref="CreateAccessTokenNotification"/> class
        /// </summary>
        /// <param name="context"></param>
        /// <param name="options"></param>
        /// <param name="request"></param>
        /// <param name="response"></param>
        /// <param name="ticket"></param>
        internal CreateAccessTokenNotification(
            IOwinContext context,
            OpenIdConnectServerOptions options,
            OpenIdConnectMessage request,
            OpenIdConnectMessage response,
            AuthenticationTicket ticket)
            : base(context, options) {
            Request = request;
            Response = response;
            AuthenticationTicket = ticket;
            Audiences = new List<string>();
        }

        /// <summary>
        /// Gets the authorization or token request.
        /// </summary>
        public new OpenIdConnectMessage Request { get; private set; }

        /// <summary>
        /// Gets the authorization or token response.
        /// </summary>
        public new OpenIdConnectMessage Response { get; private set; }

        /// <summary>
        /// Gets the authentication ticket.
        /// </summary>
        public AuthenticationTicket AuthenticationTicket { get; private set; }
        
        /// <summary>
        /// Gets the list of audiences.
        /// </summary>
        public IList<string> Audiences { get; private set; }

        /// <summary>
        /// Gets or sets the issuer address.
        /// </summary>
        public string Issuer { get; set; }

        /// <summary>
        /// Gets or sets the signature provider used to sign the access token.
        /// </summary>
        public SignatureProvider SignatureProvider { get; set; }

        /// <summary>
        /// Gets or sets the signing credentials used to sign the access token.
        /// </summary>
        public SigningCredentials SigningCredentials { get; set; }

        /// <summary>
        /// Gets or sets the data format used to serialize the authentication ticket.
        /// Note: this property is only used when <see cref="SecurityTokenHandler"/> is <c>null</c>.
        /// </summary>
        public ISecureDataFormat<AuthenticationTicket> DataFormat { get; set; }

        /// <summary>
        /// Gets or sets the security token handler used to serialize the authentication ticket.
        /// </summary>
        public SecurityTokenHandler SecurityTokenHandler { get; set; }

        /// <summary>
        /// Gets or sets the access token returned to the client application.
        /// </summary>
        public string AccessToken { get; set; }

        /// <summary>
        /// Serialize and sign the authentication ticket.
        /// </summary>
        /// <returns>The serialized and signed ticket.</returns>
        public Task<string> SerializeTicketAsync() {
            if (SecurityTokenHandler == null) {
                if (DataFormat == null) {
                    return null;
                }

                return Task.FromResult(DataFormat.Protect(AuthenticationTicket));
            }

            var handler = SecurityTokenHandler as JwtSecurityTokenHandler;
            if (handler != null) {
                // When creating an access token intended for a single audience, it's usually better
                // to format the "aud" claim as a string, but CreateToken doesn't support multiple audiences:
                // to work around this limitation, audience is initialized with a single resource and
                // JwtPayload.Aud is replaced with an array containing the multiple resources if necessary.
                // See https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-32#section-4.1.3
                var token = handler.CreateToken(
                    subject: AuthenticationTicket.Identity, issuer: Issuer,
                    audience: Audiences.ElementAtOrDefault(0),
                    signatureProvider: SignatureProvider,
                    signingCredentials: SigningCredentials,
                    notBefore: AuthenticationTicket.Properties.IssuedUtc.Value.UtcDateTime,
                    expires: AuthenticationTicket.Properties.ExpiresUtc.Value.UtcDateTime);

                if (Audiences.Count() > 1) {
                    token.Payload[JwtRegisteredClaimNames.Aud] = Audiences.ToArray();
                }

                return Task.FromResult(handler.WriteToken(token));
            }

            else {
                var token = SecurityTokenHandler.CreateToken(new SecurityTokenDescriptor {
                    Subject = AuthenticationTicket.Identity,
                    AppliesToAddress = Audiences.ElementAtOrDefault(0),
                    TokenIssuerName = Issuer,
                    EncryptingCredentials = Options.EncryptingCredentials,
                    SigningCredentials = Options.SigningCredentials,
                    Lifetime = new Lifetime(
                        AuthenticationTicket.Properties.IssuedUtc.Value.UtcDateTime,
                        AuthenticationTicket.Properties.ExpiresUtc.Value.UtcDateTime)
                });

                return Task.FromResult(SecurityTokenHandler.WriteToken(token));
            }
        }
    }
}
