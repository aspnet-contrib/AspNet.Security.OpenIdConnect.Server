/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System.Collections.Generic;
using System.IdentityModel.Protocols.WSTrust;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Protocols;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Notifications;

namespace Owin.Security.OpenIdConnect.Server {
    /// <summary>
    /// Provides context information used when issuing an access token.
    /// </summary>
    public sealed class CreateAccessTokenContext : BaseNotification<OpenIdConnectServerOptions> {
        /// <summary>
        /// Initializes a new instance of the <see cref="CreateAccessTokenContext"/> class
        /// </summary>
        /// <param name="context"></param>
        /// <param name="options"></param>
        /// <param name="request"></param>
        /// <param name="response"></param>
        /// <param name="ticket"></param>
        internal CreateAccessTokenContext(
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
        /// Note: the <see cref="AccessToken"/> property
        /// is automatically set when this method completes.
        /// </summary>
        /// <returns>The serialized and signed ticket.</returns>
        public Task<string> SerializeTicketAsync() {
            if (SecurityTokenHandler == null) {
                if (DataFormat == null) {
                    return null;
                }

                return Task.FromResult(AccessToken = DataFormat.Protect(AuthenticationTicket));
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

                if (SigningCredentials != null) {
                    var x509SecurityKey = SigningCredentials.SigningKey as X509SecurityKey;
                    if (x509SecurityKey != null) {
                        // Note: "x5t" is only added by JwtHeader's constructor if SigningCredentials is a X509SigningCredentials instance.
                        // To work around this limitation, "x5t" is manually added if a certificate can be extracted from a X509SecurityKey
                        token.Header[JwtHeaderParameterNames.X5t] = Base64UrlEncoder.Encode(x509SecurityKey.Certificate.GetCertHash());
                    }

                    object identifier;
                    if (!token.Header.TryGetValue(JwtHeaderParameterNames.Kid, out identifier) || identifier == null) {
                        // When no key identifier has been explicitly added, a "kid" is automatically
                        // inferred from the hexadecimal representation of the certificate thumbprint.
                        if (x509SecurityKey != null) {
                            identifier = x509SecurityKey.Certificate.Thumbprint;
                        }

                        // When no key identifier has been explicitly added by the developer, a "kid"
                        // is automatically inferred from the modulus if the signing key is a RSA key.
                        var rsaSecurityKey = SigningCredentials.SigningKey as RsaSecurityKey;
                        if (rsaSecurityKey != null) {
                            var algorithm = (RSA) rsaSecurityKey.GetAsymmetricAlgorithm(
                                SecurityAlgorithms.RsaSha256Signature, false);

                            // Export the RSA public key.
                            var parameters = algorithm.ExportParameters(includePrivateParameters: false);

                            // Only use the 40 first chars to match the identifier used by the JWKS endpoint.
                            identifier = Base64UrlEncoder.Encode(parameters.Modulus)
                                                         .Substring(0, 40)
                                                         .ToUpperInvariant();
                        }

                        token.Header[JwtHeaderParameterNames.Kid] = identifier;
                    }
                }

                return Task.FromResult(AccessToken = handler.WriteToken(token));
            }

            else {
                var token = SecurityTokenHandler.CreateToken(new SecurityTokenDescriptor {
                    Subject = AuthenticationTicket.Identity,
                    AppliesToAddress = Audiences.ElementAtOrDefault(0),
                    TokenIssuerName = Issuer,
                    SigningCredentials = SigningCredentials,
                    Lifetime = new Lifetime(
                        AuthenticationTicket.Properties.IssuedUtc.Value.UtcDateTime,
                        AuthenticationTicket.Properties.ExpiresUtc.Value.UtcDateTime)
                });

                return Task.FromResult(AccessToken = SecurityTokenHandler.WriteToken(token));
            }
        }
    }
}
