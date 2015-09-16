/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNet.Authentication;
using Microsoft.AspNet.Http;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace AspNet.Security.OpenIdConnect.Server {
    /// <summary>
    /// Provides context information used when issuing an identity token.
    /// </summary>
    public sealed class CreateIdentityTokenContext : BaseControlContext<OpenIdConnectServerOptions> {
        /// <summary>
        /// Initializes a new instance of the <see cref="CreateIdentityTokenContext"/> class
        /// </summary>
        /// <param name="context"></param>
        /// <param name="options"></param>
        /// <param name="request"></param>
        /// <param name="response"></param>
        /// <param name="ticket"></param>
        internal CreateIdentityTokenContext(
            HttpContext context,
            OpenIdConnectServerOptions options,
            OpenIdConnectMessage request,
            OpenIdConnectMessage response,
            AuthenticationTicket ticket)
            : base(context, options) {
            Request = request;
            Response = response;
            AuthenticationTicket = ticket;
        }

        /// <summary>
        /// Gets the authorization or token request.
        /// </summary>
        public new OpenIdConnectMessage Request { get; }

        /// <summary>
        /// Gets the authorization or token response.
        /// </summary>
        public new OpenIdConnectMessage Response { get; }

        /// <summary>
        /// Gets the list of audiences.
        /// </summary>
        public IList<string> Audiences { get; } = new List<string>();

        /// <summary>
        /// Gets or sets the issuer address.
        /// </summary>
        public string Issuer { get; set; }

        /// <summary>
        /// Gets or sets the signature provider used to sign the access token.
        /// </summary>
        public SignatureProvider SignatureProvider { get; set; }

        /// <summary>
        /// Gets or sets the signing credentials used to sign the identity token.
        /// </summary>
        public SigningCredentials SigningCredentials { get; set; }

        /// <summary>
        /// Gets or sets the security token handler used to serialize the authentication ticket.
        /// </summary>
        public JwtSecurityTokenHandler SecurityTokenHandler { get; set; }

        /// <summary>
        /// Gets or sets the identity token returned to the client application.
        /// </summary>
        public string IdentityToken { get; set; }

        /// <summary>
        /// Serialize and sign the authentication ticket.
        /// </summary>
        /// <returns>The serialized and signed ticket.</returns>
        public Task<string> SerializeTicketAsync() {
            if (SecurityTokenHandler == null) {
                return Task.FromResult<string>(null);
            }

            // Work around a bug introduced in System.IdentityModel.Tokens for ASP.NET 5.
            // See https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/issues/133
            var identity = (ClaimsIdentity) AuthenticationTicket.Principal.Identity;
            for (var actor = identity.Actor; actor != null; actor = actor.Actor) {
                actor.BootstrapContext = new JwtSecurityToken(claims: actor.Claims);
            }

            // When creating an identity token intended for a single audience, it's usually better
            // to format the "aud" claim as a string, but CreateToken doesn't support multiple audiences:
            // to work around this limitation, audience is initialized with a single resource and
            // JwtPayload.Aud is replaced with an array containing the multiple resources if necessary.
            // See http://openid.net/specs/openid-connect-core-1_0.html#IDToken
            var token = SecurityTokenHandler.CreateToken(
                subject: identity, issuer: Issuer,
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
                    // Note: unlike "kid", "x5t" is not automatically added by JwtHeader's constructor in IdentityModel for ASP.NET 5.
                    // Though not required by the specifications, this property is needed for IdentityModel for Katana to work correctly.
                    // See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server/issues/132
                    // and https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/issues/181.
                    token.Header[JwtHeaderParameterNames.X5t] = Base64UrlEncoder.Encode(x509SecurityKey.Certificate.GetCertHash());
                }

                object identifier;
                if (!token.Header.TryGetValue(JwtHeaderParameterNames.Kid, out identifier) || identifier == null) {
                    // When the token doesn't contain a "kid" parameter in the header, automatically add one
                    // using the identifier specified in the signing credentials or in the security key.
                    identifier = SigningCredentials.Kid ?? SigningCredentials.SigningKey.KeyId;

                    if (identifier == null) {
                        // When no key identifier has been explicitly added by the developer, a "kid" is automatically
                        // inferred from the hexadecimal representation of the certificate thumbprint (SHA-1).
                        if (x509SecurityKey != null) {
                            identifier = x509SecurityKey.Certificate.Thumbprint;
                        }

                        // When no key identifier has been explicitly added by the developer, a "kid"
                        // is automatically inferred from the modulus if the signing key is a RSA key.
                        var rsaSecurityKey = SigningCredentials.SigningKey as RsaSecurityKey;
                        if (rsaSecurityKey != null) {
                            // Only use the 40 first chars to match the identifier used by the JWKS endpoint.
                            identifier = Base64UrlEncoder.Encode(rsaSecurityKey.Parameters.Modulus)
                                                         .Substring(0, 40).ToUpperInvariant();
                        }
                    }

                    token.Header[JwtHeaderParameterNames.Kid] = identifier;
                }
            }

            return Task.FromResult(SecurityTokenHandler.WriteToken(token));
        }
    }
}
