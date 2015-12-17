/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.IdentityModel.Protocols.WSTrust;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Xml;
using Microsoft.IdentityModel.Protocols;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using Owin.Security.OpenIdConnect.Extensions;

namespace Owin.Security.OpenIdConnect.Server {
    internal partial class OpenIdConnectServerHandler : AuthenticationHandler<OpenIdConnectServerOptions> {
        private async Task<string> SerializeAuthorizationCodeAsync(
            ClaimsIdentity identity, AuthenticationProperties properties,
            OpenIdConnectMessage request, OpenIdConnectMessage response) {
            // properties.IssuedUtc and properties.ExpiresUtc
            // should always be preferred when explicitly set.
            if (properties.IssuedUtc == null) {
                properties.IssuedUtc = Options.SystemClock.UtcNow;
            }

            if (properties.ExpiresUtc == null) {
                properties.ExpiresUtc = properties.IssuedUtc + Options.AuthorizationCodeLifetime;
            }

            properties.SetUsage(OpenIdConnectConstants.Usages.Code);

            // Claims in authorization codes are never filtered as they are supposed to be opaque:
            // SerializeAccessTokenAsync and SerializeIdentityTokenAsync are responsible of ensuring
            // that subsequent access and identity tokens are correctly filtered.
            var ticket = new AuthenticationTicket(identity, properties);

            var notification = new SerializeAuthorizationCodeContext(Context, Options, request, response, ticket) {
                DataFormat = Options.AuthorizationCodeFormat
            };

            // By default, add the client_id to the list of the
            // presenters allowed to use the authorization code.
            if (!string.IsNullOrEmpty(request.ClientId)) {
                notification.Presenters.Add(request.ClientId);
            }

            await Options.Provider.SerializeAuthorizationCode(notification);

            if (!string.IsNullOrEmpty(notification.AuthorizationCode)) {
                return notification.AuthorizationCode;
            }

            // Allow the application to change the authentication
            // ticket from the SerializeAuthorizationCode event.
            ticket = notification.AuthenticationTicket;
            ticket.Properties.CopyTo(properties);

            // Add the intented presenters in the authentication ticket.
            if (notification.Presenters.Count != 0) {
                ticket.SetPresenters(notification.Presenters);
            }

            if (notification.DataFormat == null) {
                return null;
            }

            var key = GenerateKey(256 / 8);

            Options.Cache.Set(key,
                value: notification.DataFormat.Protect(ticket),
                absoluteExpiration: ticket.Properties.ExpiresUtc.Value);

            return key;
        }

        private async Task<string> SerializeAccessTokenAsync(
            ClaimsIdentity identity, AuthenticationProperties properties,
            OpenIdConnectMessage request, OpenIdConnectMessage response) {
            // properties.IssuedUtc and properties.ExpiresUtc
            // should always be preferred when explicitly set.
            if (properties.IssuedUtc == null) {
                properties.IssuedUtc = Options.SystemClock.UtcNow;
            }

            if (properties.ExpiresUtc == null) {
                properties.ExpiresUtc = properties.IssuedUtc + Options.AccessTokenLifetime;
            }

            properties.SetUsage(OpenIdConnectConstants.Usages.AccessToken);

            // Create a new identity containing only the filtered claims.
            // Actors identities are also filtered (delegation scenarios).
            identity = identity.Clone(claim => {
                // Never exclude ClaimTypes.NameIdentifier.
                if (string.Equals(claim.Type, ClaimTypes.NameIdentifier, StringComparison.OrdinalIgnoreCase)) {
                    return true;
                }

                // Claims whose destination is not explicitly referenced or
                // doesn't contain "token" are not included in the access token.
                return claim.HasDestination(OpenIdConnectConstants.ResponseTypes.Token);
            });

            // Create a new ticket containing the updated properties and the filtered identity.
            var ticket = new AuthenticationTicket(identity, properties);

            var notification = new SerializeAccessTokenContext(Context, Options, request, response, ticket) {
                Confidential = ticket.IsConfidential(),
                DataFormat = Options.AccessTokenFormat,
                Issuer = Context.GetIssuer(Options),
                SecurityTokenHandler = Options.AccessTokenHandler,
                SigningCredentials = Options.SigningCredentials.FirstOrDefault()
            };

            // By default, add the client_id to the list of the
            // presenters allowed to use the access token.
            if (!string.IsNullOrEmpty(request.ClientId)) {
                notification.Presenters.Add(request.ClientId);
            }

            foreach (var audience in ticket.GetResources()) {
                notification.Audiences.Add(audience);
            }

            foreach (var scope in ticket.GetScopes()) {
                notification.Scopes.Add(scope);
            }

            await Options.Provider.SerializeAccessToken(notification);

            if (!string.IsNullOrEmpty(notification.AccessToken)) {
                return notification.AccessToken;
            }

            // Allow the application to change the authentication
            // ticket from the SerializeAccessTokenAsync event.
            ticket = notification.AuthenticationTicket;
            ticket.Properties.CopyTo(properties);

            // Add the intented audiences in the authentication ticket.
            if (notification.Audiences.Count != 0) {
                ticket.SetAudiences(notification.Audiences);
            }

            // Add the intented presenters in the authentication ticket.
            if (notification.Presenters.Count != 0) {
                ticket.SetPresenters(notification.Presenters);
            }

            // Add the intented scopes in the authentication ticket.
            if (notification.Scopes.Count != 0) {
                ticket.SetScopes(notification.Scopes);
            }

            if (notification.SecurityTokenHandler == null) {
                return notification.DataFormat?.Protect(ticket);
            }

            // Store the "usage" property as a claim.
            ticket.Identity.AddClaim(OpenIdConnectConstants.Properties.Usage, ticket.Properties.GetUsage());

            // If the ticket is marked as confidential, add a new
            // "confidential" claim in the security token.
            if (notification.Confidential) {
                ticket.Identity.AddClaim(new Claim(OpenIdConnectConstants.Properties.Confidential, "true", ClaimValueTypes.Boolean));
            }

            // Create a new claim per scope item, that will result
            // in a "scope" array being added in the access token.
            foreach (var scope in notification.Scopes) {
                ticket.Identity.AddClaim(OpenIdConnectConstants.Claims.Scope, scope);
            }

            var handler = notification.SecurityTokenHandler as JwtSecurityTokenHandler;
            if (handler != null) {
                // Remove the ClaimTypes.NameIdentifier claims to avoid getting duplicate claims.
                // Note: the "sub" claim is automatically mapped by JwtSecurityTokenHandler
                // to ClaimTypes.NameIdentifier when validating a JWT token.
                // Note: make sure to call ToArray() to avoid an InvalidOperationException
                // on old versions of Mono, where FindAll() is implemented using an iterator.
                foreach (var claim in ticket.Identity.FindAll(ClaimTypes.NameIdentifier).ToArray()) {
                    ticket.Identity.RemoveClaim(claim);
                }

                // Note: when used as an access token, a JWT token doesn't have to expose a "sub" claim
                // but the name identifier claim is used as a substitute when it has been explicitly added.
                // See https://tools.ietf.org/html/rfc7519#section-4.1.2
                var subject = identity.FindFirst(JwtRegisteredClaimNames.Sub);
                if (subject == null) {
                    var identifier = identity.FindFirst(ClaimTypes.NameIdentifier);
                    if (identifier != null) {
                        identity.AddClaim(JwtRegisteredClaimNames.Sub, identifier.Value);
                    }
                }

                // Store the audiences as claims.
                foreach (var audience in notification.Audiences) {
                    ticket.Identity.AddClaim(JwtRegisteredClaimNames.Aud, audience);
                }

                switch (notification.Presenters.Count) {
                    case 0: break;

                    case 1:
                        identity.AddClaim(JwtRegisteredClaimNames.Azp, notification.Presenters[0]);
                        break;

                    default:
                        Options.Logger.WriteWarning("Multiple presenters have been associated with the access token " +
                                                    "but the JWT format only accepts single values.");

                        // Only add the first authorized party.
                        identity.AddClaim(JwtRegisteredClaimNames.Azp, notification.Presenters[0]);
                        break;
                }

                var token = handler.CreateToken(
                    subject: ticket.Identity,
                    issuer: notification.Issuer,
                    signingCredentials: notification.SigningCredentials,
                    notBefore: ticket.Properties.IssuedUtc.Value.UtcDateTime,
                    expires: ticket.Properties.ExpiresUtc.Value.UtcDateTime);

                token.Payload[JwtRegisteredClaimNames.Iat] = EpochTime.GetIntDate(ticket.Properties.IssuedUtc.Value.UtcDateTime);

                if (notification.SigningCredentials != null) {
                    var x509SecurityKey = notification.SigningCredentials.SigningKey as X509SecurityKey;
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

                        var x509SigningCredentials = notification.SigningCredentials as X509SigningCredentials;
                        if (x509SigningCredentials != null) {
                            identifier = x509SigningCredentials.Certificate.Thumbprint;
                        }

                        // When no key identifier has been explicitly added by the developer, a "kid"
                        // is automatically inferred from the modulus if the signing key is a RSA key.
                        var rsaSecurityKey = notification.SigningCredentials.SigningKey as RsaSecurityKey;
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

                        if (identifier != null) {
                            token.Header[JwtHeaderParameterNames.Kid] = identifier;
                        }
                    }
                }

                return handler.WriteToken(token);
            }

            else {
                var descriptor = new SecurityTokenDescriptor {
                    Subject = ticket.Identity,
                    AppliesToAddress = notification.Audiences.ElementAtOrDefault(0),
                    TokenIssuerName = notification.Issuer,
                    EncryptingCredentials = notification.EncryptingCredentials,
                    SigningCredentials = notification.SigningCredentials,
                    Lifetime = new Lifetime(
                        notification.AuthenticationTicket.Properties.IssuedUtc.Value.UtcDateTime,
                        notification.AuthenticationTicket.Properties.ExpiresUtc.Value.UtcDateTime)
                };

                // When the encrypting credentials use an asymmetric key, replace them by a
                // EncryptedKeyEncryptingCredentials instance to generate a symmetric key.
                if (descriptor.EncryptingCredentials != null &&
                    descriptor.EncryptingCredentials.SecurityKey is AsymmetricSecurityKey) {
                    // Note: EncryptedKeyEncryptingCredentials automatically generates an in-memory key
                    // that will be encrypted using the original credentials and added to the resulting token
                    // if the security token handler fully supports token encryption (e.g SAML or SAML2).
                    descriptor.EncryptingCredentials = new EncryptedKeyEncryptingCredentials(
                        wrappingCredentials: notification.EncryptingCredentials, keySizeInBits: 256,
                        encryptionAlgorithm: SecurityAlgorithms.Aes256Encryption);
                }

                var token = notification.SecurityTokenHandler.CreateToken(descriptor);

                // Note: the security token is manually serialized to prevent
                // an exception from being thrown if the handler doesn't implement
                // the SecurityTokenHandler.WriteToken overload returning a string.
                var builder = new StringBuilder();
                using (var writer = XmlWriter.Create(builder, new XmlWriterSettings {
                    Encoding = new UTF8Encoding(false), OmitXmlDeclaration = true })) {
                    notification.SecurityTokenHandler.WriteToken(writer, token);
                }

                return builder.ToString();
            }
        }

        private async Task<string> SerializeIdentityTokenAsync(
            ClaimsIdentity identity, AuthenticationProperties properties,
            OpenIdConnectMessage request, OpenIdConnectMessage response) {
            // properties.IssuedUtc and properties.ExpiresUtc
            // should always be preferred when explicitly set.
            if (properties.IssuedUtc == null) {
                properties.IssuedUtc = Options.SystemClock.UtcNow;
            }

            if (properties.ExpiresUtc == null) {
                properties.ExpiresUtc = properties.IssuedUtc + Options.IdentityTokenLifetime;
            }

            properties.SetUsage(OpenIdConnectConstants.Usages.IdToken);

            // Replace the identity by a new one containing only the filtered claims.
            // Actors identities are also filtered (delegation scenarios).
            identity = identity.Clone(claim => {
                // Never exclude ClaimTypes.NameIdentifier.
                if (string.Equals(claim.Type, ClaimTypes.NameIdentifier, StringComparison.OrdinalIgnoreCase)) {
                    return true;
                }

                // Claims whose destination is not explicitly referenced or
                // doesn't contain "id_token" are not included in the identity token.
                return claim.HasDestination(OpenIdConnectConstants.ResponseTypes.IdToken);
            });

            // Create a new ticket containing the updated properties and the filtered identity.
            var ticket = new AuthenticationTicket(identity, properties);

            var notification = new SerializeIdentityTokenContext(Context, Options, request, response, ticket) {
                Confidential = ticket.IsConfidential(),
                Issuer = Context.GetIssuer(Options),
                Nonce = request.Nonce,
                SecurityTokenHandler = Options.IdentityTokenHandler,
                SigningCredentials = Options.SigningCredentials.FirstOrDefault(),
                Subject = identity.GetClaim(ClaimTypes.NameIdentifier)
            };

            // If a nonce was present in the authorization request, it MUST
            // be included in the id_token generated by the token endpoint.
            // See http://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
            if (request.IsAuthorizationCodeGrantType()) {
                // Restore the nonce stored in the authentication
                // ticket extracted from the authorization code.
                notification.Nonce = ticket.GetNonce();
            }

            // By default, add the client_id to the list of the
            // presenters allowed to use the identity token.
            if (!string.IsNullOrEmpty(request.ClientId)) {
                notification.Audiences.Add(request.ClientId);
                notification.Presenters.Add(request.ClientId);
            }

            if (!string.IsNullOrEmpty(response.Code)) {
                using (var algorithm = HashAlgorithm.Create(SecurityAlgorithms.Sha256Digest)) {
                    // Create the c_hash using the authorization code returned by SerializeAuthorizationCodeAsync.
                    var hash = algorithm.ComputeHash(Encoding.ASCII.GetBytes(response.Code));

                    // Note: only the left-most half of the hash of the octets is used.
                    // See http://openid.net/specs/openid-connect-core-1_0.html#HybridIDToken
                    notification.CHash = Base64UrlEncoder.Encode(hash, 0, hash.Length / 2);
                }
            }

            if (!string.IsNullOrEmpty(response.AccessToken)) {
                using (var algorithm = HashAlgorithm.Create(SecurityAlgorithms.Sha256Digest)) {
                    // Create the at_hash using the access token returned by SerializeAccessTokenAsync.
                    var hash = algorithm.ComputeHash(Encoding.ASCII.GetBytes(response.AccessToken));

                    // Note: only the left-most half of the hash of the octets is used.
                    // See http://openid.net/specs/openid-connect-core-1_0.html#CodeIDToken
                    notification.AtHash = Base64UrlEncoder.Encode(hash, 0, hash.Length / 2);
                }
            }

            await Options.Provider.SerializeIdentityToken(notification);

            if (!string.IsNullOrEmpty(notification.IdentityToken)) {
                return notification.IdentityToken;
            }

            // Allow the application to change the authentication
            // ticket from the SerializeIdentityTokenAsync event.
            ticket = notification.AuthenticationTicket;
            ticket.Properties.CopyTo(properties);

            if (notification.SecurityTokenHandler == null) {
                return null;
            }

            if (string.IsNullOrEmpty(notification.Subject)) {
                Options.Logger.WriteError("A unique identifier cannot be found to generate a 'sub' claim. " +
                                          "Make sure to either add a 'sub' or a 'ClaimTypes.NameIdentifier' claim " +
                                          "in the returned ClaimsIdentity before calling SignIn.");

                return null;
            }

            // Remove the ClaimTypes.NameIdentifier claims to avoid getting duplicate claims.
            // Note: the "sub" claim is automatically mapped by JwtSecurityTokenHandler
            // to ClaimTypes.NameIdentifier when validating a JWT token.
            // Note: make sure to call ToArray() to avoid an InvalidOperationException
            // on old versions of Mono, where FindAll() is implemented using an iterator.
            foreach (var claim in ticket.Identity.FindAll(ClaimTypes.NameIdentifier).ToArray()) {
                ticket.Identity.RemoveClaim(claim);
            }

            // Store the unique subject identifier as a claim.
            ticket.Identity.AddClaim(JwtRegisteredClaimNames.Sub, notification.Subject);

            // Store the "usage" property as a claim.
            ticket.Identity.AddClaim(OpenIdConnectConstants.Properties.Usage, ticket.Properties.GetUsage());

            // Store the audiences as claims.
            foreach (var audience in notification.Audiences) {
                ticket.Identity.AddClaim(JwtRegisteredClaimNames.Aud, audience);
            }

            if (!string.IsNullOrEmpty(notification.AtHash)) {
                ticket.Identity.AddClaim("at_hash", notification.AtHash);
            }

            if (!string.IsNullOrEmpty(notification.CHash)) {
                ticket.Identity.AddClaim(JwtRegisteredClaimNames.CHash, notification.CHash);
            }

            if (!string.IsNullOrEmpty(notification.Nonce)) {
                ticket.Identity.AddClaim(JwtRegisteredClaimNames.Nonce, notification.Nonce);
            }

            // If the ticket is marked as confidential, add a new
            // "confidential" claim in the security token.
            if (notification.Confidential) {
                ticket.Identity.AddClaim(new Claim(OpenIdConnectConstants.Properties.Confidential, "true", ClaimValueTypes.Boolean));
            }

            switch (notification.Presenters.Count) {
                case 0: break;

                case 1:
                    identity.AddClaim(JwtRegisteredClaimNames.Azp, notification.Presenters[0]);
                    break;

                default:
                    Options.Logger.WriteWarning("Multiple presenters have been associated with the identity token " +
                                                "but the JWT format only accepts single values.");

                    // Only add the first authorized party.
                    identity.AddClaim(JwtRegisteredClaimNames.Azp, notification.Presenters[0]);
                    break;
            }

            var token = notification.SecurityTokenHandler.CreateToken(
                subject: ticket.Identity,
                issuer: notification.Issuer,
                signingCredentials: notification.SigningCredentials,
                notBefore: notification.AuthenticationTicket.Properties.IssuedUtc.Value.UtcDateTime,
                expires: notification.AuthenticationTicket.Properties.ExpiresUtc.Value.UtcDateTime);

            token.Payload[JwtRegisteredClaimNames.Iat] = EpochTime.GetIntDate(ticket.Properties.IssuedUtc.Value.UtcDateTime);

            if (notification.SigningCredentials != null) {
                var x509SecurityKey = notification.SigningCredentials.SigningKey as X509SecurityKey;
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

                    var x509SigningCredentials = notification.SigningCredentials as X509SigningCredentials;
                    if (x509SigningCredentials != null) {
                        identifier = x509SigningCredentials.Certificate.Thumbprint;
                    }

                    // When no key identifier has been explicitly added by the developer, a "kid"
                    // is automatically inferred from the modulus if the signing key is a RSA key.
                    var rsaSecurityKey = notification.SigningCredentials.SigningKey as RsaSecurityKey;
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

                    if (identifier != null) {
                        token.Header[JwtHeaderParameterNames.Kid] = identifier;
                    }
                }
            }

            return notification.SecurityTokenHandler.WriteToken(token);
        }

        private async Task<string> SerializeRefreshTokenAsync(
            ClaimsIdentity identity, AuthenticationProperties properties,
            OpenIdConnectMessage request, OpenIdConnectMessage response) {
            // properties.IssuedUtc and properties.ExpiresUtc
            // should always be preferred when explicitly set.
            if (properties.IssuedUtc == null) {
                properties.IssuedUtc = Options.SystemClock.UtcNow;
            }

            if (properties.ExpiresUtc == null) {
                properties.ExpiresUtc = properties.IssuedUtc + Options.RefreshTokenLifetime;
            }

            properties.SetUsage(OpenIdConnectConstants.Usages.RefreshToken);

            // Claims in refresh tokens are never filtered as they are supposed to be opaque:
            // SerializeAccessTokenAsync and SerializeIdentityTokenAsync are responsible of ensuring
            // that subsequent access and identity tokens are correctly filtered.
            var ticket = new AuthenticationTicket(identity, properties);

            var notification = new SerializeRefreshTokenContext(Context, Options, request, response, ticket) {
                DataFormat = Options.RefreshTokenFormat
            };

            // By default, add the client_id to the list of the
            // presenters allowed to use the refresh token.
            if (!string.IsNullOrEmpty(request.ClientId)) {
                notification.Presenters.Add(request.ClientId);
            }

            await Options.Provider.SerializeRefreshToken(notification);

            if (!string.IsNullOrEmpty(notification.RefreshToken)) {
                return notification.RefreshToken;
            }

            // Allow the application to change the authentication
            // ticket from the SerializeRefreshTokenAsync event.
            ticket = notification.AuthenticationTicket;
            ticket.Properties.CopyTo(properties);

            // Add the intented presenters in the authentication ticket.
            if (notification.Presenters.Count != 0) {
                ticket.SetPresenters(notification.Presenters);
            }

            return notification.DataFormat?.Protect(ticket);
        }

        private async Task<AuthenticationTicket> DeserializeAuthorizationCodeAsync(string code, OpenIdConnectMessage request) {
            var notification = new DeserializeAuthorizationCodeContext(Context, Options, request, code) {
                DataFormat = Options.AuthorizationCodeFormat
            };

            await Options.Provider.DeserializeAuthorizationCode(notification);

            // Directly return the authentication ticket if one
            // has been provided by DeserializeAuthorizationCode.
            if (notification.AuthenticationTicket != null) {
                return notification.AuthenticationTicket;
            }

            var value = (string) Options.Cache.Get(code);
            if (string.IsNullOrEmpty(value)) {
                return null;
            }

            // Because authorization codes are guaranteed to be unique, make sure
            // to remove the current code from the global store before using it.
            Options.Cache.Remove(code);

            var ticket = notification.DataFormat?.Unprotect(value);
            if (ticket == null) {
                return null;
            }

            // Ensure the received ticket is an authorization code.
            if (!ticket.IsAuthorizationCode()) {
                Options.Logger.WriteVerbose($"The received token was not an authorization code: {code}.");

                return null;
            }

            return ticket;
        }

        private async Task<AuthenticationTicket> DeserializeAccessTokenAsync(string token, OpenIdConnectMessage request) {
            var notification = new DeserializeAccessTokenContext(Context, Options, request, token) {
                DataFormat = Options.AccessTokenFormat,
                Issuer = Context.GetIssuer(Options),
                SecurityTokenHandler = Options.AccessTokenHandler,
                SigningCredentials = Options.SigningCredentials.FirstOrDefault()
            };

            await Options.Provider.DeserializeAccessToken(notification);

            // Directly return the authentication ticket if one
            // has been provided by DeserializeAccessToken.
            if (notification.AuthenticationTicket != null) {
                return notification.AuthenticationTicket;
            }

            var handler = notification.SecurityTokenHandler as ISecurityTokenValidator;
            if (handler == null) {
                return notification.DataFormat?.Unprotect(token);
            }

            // Create new validation parameters to validate the security token.
            // ValidateAudience and ValidateLifetime are always set to false:
            // if necessary, the audience and the expiration can be validated
            // in InvokeValidationEndpointAsync or InvokeTokenEndpointAsync.
            var parameters = new TokenValidationParameters {
                IssuerSigningKey = notification.SigningCredentials.SigningKey,
                ValidIssuer = notification.Issuer,
                ValidateAudience = false,
                ValidateLifetime = false
            };

            SecurityToken securityToken;
            ClaimsPrincipal principal;

            try {
                principal = handler.ValidateToken(token, parameters, out securityToken);
            }

            catch (Exception exception) {
                Options.Logger.WriteVerbose($"An exception occured when deserializing an access token: {exception.Message}");

                return null;
            }

            // Parameters stored in AuthenticationProperties are lost
            // when the identity token is serialized using a security token handler.
            // To mitigate that, they are inferred from the claims or the security token.
            var properties = new AuthenticationProperties {
                ExpiresUtc = securityToken.ValidTo,
                IssuedUtc = securityToken.ValidFrom
            };

            var audiences = principal.FindAll(JwtRegisteredClaimNames.Aud);
            if (audiences.Any()) {
                properties.SetAudiences(audiences.Select(claim => claim.Value));
            }

            var presenters = principal.FindAll(JwtRegisteredClaimNames.Azp);
            if (presenters.Any()) {
                properties.SetPresenters(presenters.Select(claim => claim.Value));
            }

            var scopes = principal.FindAll(OpenIdConnectConstants.Claims.Scope);
            if (scopes.Any()) {
                properties.SetScopes(scopes.Select(claim => claim.Value));
            }

            var usage = principal.FindFirst(OpenIdConnectConstants.Properties.Usage);
            if (usage != null) {
                properties.SetUsage(usage.Value);
            }

            var confidential = principal.FindFirst(OpenIdConnectConstants.Properties.Confidential);
            if (confidential != null && string.Equals(confidential.Value, "true", StringComparison.OrdinalIgnoreCase)) {
                properties.Dictionary[OpenIdConnectConstants.Properties.Confidential] = "true";
            }

            // Ensure the received ticket is an access token.
            var ticket = new AuthenticationTicket((ClaimsIdentity) principal.Identity, properties);
            if (!ticket.IsAccessToken()) {
                Options.Logger.WriteVerbose($"The received token was not an access token: {token}.");

                return null;
            }

            return ticket;
        }

        private async Task<AuthenticationTicket> DeserializeIdentityTokenAsync(string token, OpenIdConnectMessage request) {
            var notification = new DeserializeIdentityTokenContext(Context, Options, request, token) {
                Issuer = Context.GetIssuer(Options),
                SecurityTokenHandler = Options.IdentityTokenHandler,
                SigningCredentials = Options.SigningCredentials.FirstOrDefault()
            };

            await Options.Provider.DeserializeIdentityToken(notification);

            // Directly return the authentication ticket if one
            // has been provided by DeserializeIdentityToken.
            if (notification.AuthenticationTicket != null) {
                return notification.AuthenticationTicket;
            }

            if (notification.SecurityTokenHandler == null) {
                return null;
            }

            // Create new validation parameters to validate the security token.
            // ValidateAudience and ValidateLifetime are always set to false:
            // if necessary, the audience and the expiration can be validated
            // in InvokeValidationEndpointAsync or InvokeTokenEndpointAsync.
            var parameters = new TokenValidationParameters {
                IssuerSigningKey = notification.SigningCredentials.SigningKey,
                ValidIssuer = notification.Issuer,
                ValidateAudience = false,
                ValidateLifetime = false
            };

            SecurityToken securityToken;
            ClaimsPrincipal principal;

            try {
                principal = notification.SecurityTokenHandler.ValidateToken(token, parameters, out securityToken);
            }

            catch (Exception exception) {
                Options.Logger.WriteVerbose($"An exception occured when deserializing an identity token: {exception.Message}");

                return null;
            }

            // Parameters stored in AuthenticationProperties are lost
            // when the identity token is serialized using a security token handler.
            // To mitigate that, they are inferred from the claims or the security token.
            var properties = new AuthenticationProperties {
                ExpiresUtc = securityToken.ValidTo,
                IssuedUtc = securityToken.ValidFrom
            };

            var audiences = principal.FindAll(JwtRegisteredClaimNames.Aud);
            if (audiences.Any()) {
                properties.SetAudiences(audiences.Select(claim => claim.Value));
            }

            var presenters = principal.FindAll(JwtRegisteredClaimNames.Azp);
            if (presenters.Any()) {
                properties.SetPresenters(presenters.Select(claim => claim.Value));
            }

            var usage = principal.FindFirst(OpenIdConnectConstants.Properties.Usage);
            if (usage != null) {
                properties.SetUsage(usage.Value);
            }

            var confidential = principal.FindFirst(OpenIdConnectConstants.Properties.Confidential);
            if (confidential != null && string.Equals(confidential.Value, "true", StringComparison.OrdinalIgnoreCase)) {
                properties.Dictionary[OpenIdConnectConstants.Properties.Confidential] = "true";
            }

            // Ensure the received ticket is an identity token.
            var ticket = new AuthenticationTicket((ClaimsIdentity) principal.Identity, properties);
            if (!ticket.IsIdentityToken()) {
                Options.Logger.WriteVerbose($"The received token was not an identity token: {token}.");

                return null;
            }

            return ticket;
        }

        private async Task<AuthenticationTicket> DeserializeRefreshTokenAsync(string token, OpenIdConnectMessage request) {
            var notification = new DeserializeRefreshTokenContext(Context, Options, request, token) {
                DataFormat = Options.RefreshTokenFormat
            };

            await Options.Provider.DeserializeRefreshToken(notification);

            // Directly return the authentication ticket if one
            // has been provided by DeserializeRefreshToken.
            if (notification.AuthenticationTicket != null) {
                return notification.AuthenticationTicket;
            }

            var ticket = notification.DataFormat?.Unprotect(token);
            if (ticket == null) {
                return null;
            }

            // Ensure the received ticket is an identity token.
            if (!ticket.IsRefreshToken()) {
                Options.Logger.WriteVerbose($"The received token was not a refresh token: {token}.");

                return null;
            }

            return ticket;
        }
    }
}
