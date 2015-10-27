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
using Microsoft.IdentityModel.Protocols;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using Owin.Security.OpenIdConnect.Extensions;

namespace Owin.Security.OpenIdConnect.Server {
    internal partial class OpenIdConnectServerHandler : AuthenticationHandler<OpenIdConnectServerOptions> {
        private async Task<string> CreateAuthorizationCodeAsync(
            ClaimsIdentity identity, AuthenticationProperties properties,
            OpenIdConnectMessage request, OpenIdConnectMessage response) {
            try {
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
                // CreateAccessTokenAsync and CreateIdentityTokenAsync are responsible of ensuring
                // that subsequent access and identity tokens are correctly filtered.
                var ticket = new AuthenticationTicket(identity, properties);

                var notification = new CreateAuthorizationCodeContext(Context, Options, request, response, ticket) {
                    DataFormat = Options.AuthorizationCodeFormat
                };

                // Sets the default authorization code serializer.
                notification.Serializer = payload => {
                    return Task.FromResult(notification.DataFormat?.Protect(payload));
                };

                await Options.Provider.CreateAuthorizationCode(notification);

                // Treat a non-null authorization code like an implicit HandleResponse call.
                if (notification.HandledResponse || !string.IsNullOrEmpty(notification.AuthorizationCode)) {
                    return notification.AuthorizationCode;
                }

                else if (notification.Skipped) {
                    return null;
                }

                // Allow the application to change the authentication
                // ticket from the CreateAuthorizationCode event.
                ticket = notification.AuthenticationTicket;
                ticket.Properties.CopyTo(properties);

                var key = GenerateKey(256 / 8);

                Options.Cache.Set(key,
                    value: await notification.SerializeTicketAsync(),
                    absoluteExpiration: ticket.Properties.ExpiresUtc.Value);

                return key;
            }

            catch (Exception exception) {
                Options.Logger.WriteWarning("An exception occured when serializing an authorization code.", exception);

                return null;
            }
        }

        private async Task<string> CreateAccessTokenAsync(
            ClaimsIdentity identity, AuthenticationProperties properties,
            OpenIdConnectMessage request, OpenIdConnectMessage response) {
            try {
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
                    // ClaimTypes.NameIdentifier and JwtRegisteredClaimNames.Sub are never excluded.
                    if (string.Equals(claim.Type, ClaimTypes.NameIdentifier, StringComparison.Ordinal) ||
                        string.Equals(claim.Type, JwtRegisteredClaimNames.Sub, StringComparison.Ordinal)) {
                        return true;
                    }

                    // Claims whose destination is not explicitly referenced or
                    // doesn't contain "token" are not included in the access token.
                    return claim.HasDestination(OpenIdConnectConstants.ResponseTypes.Token);
                });

                // List the client application as an authorized party.
                if (!string.IsNullOrEmpty(request.ClientId)) {
                    identity.AddClaim(JwtRegisteredClaimNames.Azp, request.ClientId);
                }

                // Create a new claim per scope item, that will result
                // in a "scope" array being added in the access token.
                foreach (var scope in properties.GetScopes()) {
                    identity.AddClaim(OpenIdConnectConstants.Claims.Scope, scope);
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

                // Remove the ClaimTypes.NameIdentifier claims to avoid getting duplicate claims.
                // Note: the "sub" claim is automatically mapped by JwtSecurityTokenHandler
                // to ClaimTypes.NameIdentifier when validating a JWT token.
                // Note: make sure to call ToArray() to avoid an InvalidOperationException
                // on old versions of Mono, where FindAll() is implemented using an iterator.
                foreach (var claim in identity.FindAll(ClaimTypes.NameIdentifier).ToArray()) {
                    identity.RemoveClaim(claim);
                }

                // Create a new ticket containing the updated properties and the filtered identity.
                var ticket = new AuthenticationTicket(identity, properties);

                var notification = new CreateAccessTokenContext(Context, Options, request, response, ticket) {
                    DataFormat = Options.AccessTokenFormat,
                    Issuer = Context.GetIssuer(Options),
                    SecurityTokenHandler = Options.AccessTokenHandler,
                    SignatureProvider = Options.SignatureProvider,
                    SigningCredentials = Options.SigningCredentials.FirstOrDefault()
                };

                foreach (var audience in properties.GetResources()) {
                    notification.Audiences.Add(audience);
                }

                // Sets the default access token serializer.
                notification.Serializer = payload => {
                    if (notification.SecurityTokenHandler == null) {
                        return Task.FromResult(notification.DataFormat?.Protect(payload));
                    }

                    // Store the "usage" property as a claim.
                    payload.Identity.AddClaim(OpenIdConnectConstants.Extra.Usage, payload.Properties.GetUsage());

                    // Store the audiences as claims.
                    foreach (var audience in notification.Audiences) {
                        identity.AddClaim(JwtRegisteredClaimNames.Aud, audience);
                    }

                    var handler = notification.SecurityTokenHandler as JwtSecurityTokenHandler;
                    if (handler != null) {
                        var token = handler.CreateToken(
                            subject: payload.Identity,
                            issuer: notification.Issuer,
                            signatureProvider: notification.SignatureProvider,
                            signingCredentials: notification.SigningCredentials,
                            notBefore: payload.Properties.IssuedUtc.Value.UtcDateTime,
                            expires: payload.Properties.ExpiresUtc.Value.UtcDateTime);

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

                                token.Header[JwtHeaderParameterNames.Kid] = identifier;
                            }
                        }

                        return Task.FromResult(handler.WriteToken(token));
                    }

                    else {
                        var token = notification.SecurityTokenHandler.CreateToken(new SecurityTokenDescriptor {
                            Subject = notification.AuthenticationTicket.Identity,
                            AppliesToAddress = notification.Audiences.ElementAtOrDefault(0),
                            TokenIssuerName = notification.Issuer,
                            SigningCredentials = notification.SigningCredentials,
                            Lifetime = new Lifetime(
                                notification.AuthenticationTicket.Properties.IssuedUtc.Value.UtcDateTime,
                                notification.AuthenticationTicket.Properties.ExpiresUtc.Value.UtcDateTime)
                        });

                        return Task.FromResult(notification.SecurityTokenHandler.WriteToken(token));
                    }
                };

                await Options.Provider.CreateAccessToken(notification);

                // Treat a non-null access token like an implicit HandleResponse call.
                if (notification.HandledResponse || !string.IsNullOrEmpty(notification.AccessToken)) {
                    return notification.AccessToken;
                }

                else if (notification.Skipped) {
                    return null;
                }

                // Allow the application to change the authentication
                // ticket from the CreateAccessTokenAsync event.
                ticket = notification.AuthenticationTicket;
                ticket.Properties.CopyTo(properties);

                return await notification.SerializeTicketAsync();
            }

            catch (Exception exception) {
                Options.Logger.WriteWarning("An exception occured when serializing an access token.", exception);

                return null;
            }
        }

        private async Task<string> CreateIdentityTokenAsync(
            ClaimsIdentity identity, AuthenticationProperties properties,
            OpenIdConnectMessage request, OpenIdConnectMessage response) {
            try {
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
                    // ClaimTypes.NameIdentifier and JwtRegisteredClaimNames.Sub are never excluded.
                    if (string.Equals(claim.Type, ClaimTypes.NameIdentifier, StringComparison.Ordinal) ||
                        string.Equals(claim.Type, JwtRegisteredClaimNames.Sub, StringComparison.Ordinal)) {
                        return true;
                    }

                    // Claims whose destination is not explicitly referenced or
                    // doesn't contain "id_token" are not included in the identity token.
                    return claim.HasDestination(OpenIdConnectConstants.ResponseTypes.IdToken);
                });

                identity.AddClaim(JwtRegisteredClaimNames.Iat,
                    EpochTime.GetIntDate(properties.IssuedUtc.Value.UtcDateTime).ToString());

                if (!string.IsNullOrEmpty(response.Code)) {
                    using (var algorithm = HashAlgorithm.Create(SecurityAlgorithms.Sha256Digest)) {
                        // Create the c_hash using the authorization code returned by CreateAuthorizationCodeAsync.
                        var hash = algorithm.ComputeHash(Encoding.ASCII.GetBytes(response.Code));

                        // Note: only the left-most half of the hash of the octets is used.
                        // See http://openid.net/specs/openid-connect-core-1_0.html#HybridIDToken
                        identity.AddClaim(JwtRegisteredClaimNames.CHash, Base64UrlEncoder.Encode(hash, 0, hash.Length / 2));
                    }
                }

                if (!string.IsNullOrEmpty(response.AccessToken)) {
                    using (var algorithm = HashAlgorithm.Create(SecurityAlgorithms.Sha256Digest)) {
                        // Create the at_hash using the access token returned by CreateAccessTokenAsync.
                        var hash = algorithm.ComputeHash(Encoding.ASCII.GetBytes(response.AccessToken));

                        // Note: only the left-most half of the hash of the octets is used.
                        // See http://openid.net/specs/openid-connect-core-1_0.html#CodeIDToken
                        identity.AddClaim("at_hash", Base64UrlEncoder.Encode(hash, 0, hash.Length / 2));
                    }
                }

                var nonce = request.Nonce;

                // If a nonce was present in the authorization request, it MUST
                // be included in the id_token generated by the token endpoint.
                // See http://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
                if (request.IsAuthorizationCodeGrantType()) {
                    // Restore the nonce stored in the authentication
                    // ticket extracted from the authorization code.
                    nonce = properties.GetNonce();
                }

                if (!string.IsNullOrEmpty(nonce)) {
                    identity.AddClaim(JwtRegisteredClaimNames.Nonce, nonce);
                }

                // While the 'sub' claim is declared mandatory by the OIDC specs,
                // it is not always issued as-is by the authorization servers.
                // When missing, the name identifier claim is used as a substitute.
                // See http://openid.net/specs/openid-connect-core-1_0.html#IDToken
                var subject = identity.FindFirst(JwtRegisteredClaimNames.Sub);
                if (subject == null) {
                    var identifier = identity.FindFirst(ClaimTypes.NameIdentifier);
                    if (identifier == null) {
                        throw new InvalidOperationException(
                            "A unique identifier cannot be found to generate a 'sub' claim. " +
                            "Make sure to either add a 'sub' or a 'ClaimTypes.NameIdentifier' claim " +
                            "in the returned ClaimsIdentity before calling SignIn.");
                    }

                    identity.AddClaim(JwtRegisteredClaimNames.Sub, identifier.Value);
                }

                // Remove the ClaimTypes.NameIdentifier claims to avoid getting duplicate claims.
                // Note: the "sub" claim is automatically mapped by JwtSecurityTokenHandler
                // to ClaimTypes.NameIdentifier when validating a JWT token.
                // Note: make sure to call ToArray() to avoid an InvalidOperationException
                // on old versions of Mono, where FindAll() is implemented using an iterator.
                foreach (var claim in identity.FindAll(ClaimTypes.NameIdentifier).ToArray()) {
                    identity.RemoveClaim(claim);
                }

                // Create a new ticket containing the updated properties and the filtered identity.
                var ticket = new AuthenticationTicket(identity, properties);

                var notification = new CreateIdentityTokenContext(Context, Options, request, response, ticket) {
                    Audiences = { request.ClientId },
                    Issuer = Context.GetIssuer(Options),
                    SecurityTokenHandler = Options.IdentityTokenHandler,
                    SignatureProvider = Options.SignatureProvider,
                    SigningCredentials = Options.SigningCredentials.FirstOrDefault()
                };

                // Sets the default identity token serializer.
                notification.Serializer = payload => {
                    if (notification.SecurityTokenHandler == null) {
                        return Task.FromResult<string>(null);
                    }

                    // Store the "usage" property as a claim.
                    payload.Identity.AddClaim(OpenIdConnectConstants.Extra.Usage, properties.GetUsage());

                    // Store the audiences as claims.
                    foreach (var audience in notification.Audiences) {
                        identity.AddClaim(JwtRegisteredClaimNames.Aud, audience);
                    }

                    var token = notification.SecurityTokenHandler.CreateToken(
                        subject: payload.Identity,
                        issuer: notification.Issuer,
                        signatureProvider: notification.SignatureProvider,
                        signingCredentials: notification.SigningCredentials,
                        notBefore: notification.AuthenticationTicket.Properties.IssuedUtc.Value.UtcDateTime,
                        expires: notification.AuthenticationTicket.Properties.ExpiresUtc.Value.UtcDateTime);

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

                            token.Header[JwtHeaderParameterNames.Kid] = identifier;
                        }
                    }

                    return Task.FromResult(notification.SecurityTokenHandler.WriteToken(token));
                };

                await Options.Provider.CreateIdentityToken(notification);

                // Treat a non-null identity token like an implicit HandleResponse call.
                if (notification.HandledResponse || !string.IsNullOrEmpty(notification.IdentityToken)) {
                    return notification.IdentityToken;
                }

                else if (notification.Skipped) {
                    return null;
                }

                // Allow the application to change the authentication
                // ticket from the CreateIdentityTokenAsync event.
                ticket = notification.AuthenticationTicket;
                ticket.Properties.CopyTo(properties);

                return await notification.SerializeTicketAsync();
            }

            catch (Exception exception) {
                Options.Logger.WriteWarning("An exception occured when serializing an identity token.", exception);

                return null;
            }
        }

        private async Task<string> CreateRefreshTokenAsync(
            ClaimsIdentity identity, AuthenticationProperties properties,
            OpenIdConnectMessage request, OpenIdConnectMessage response) {
            try {
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
                // CreateAccessTokenAsync and CreateIdentityTokenAsync are responsible of ensuring
                // that subsequent access and identity tokens are correctly filtered.
                var ticket = new AuthenticationTicket(identity, properties);

                var notification = new CreateRefreshTokenContext(Context, Options, request, response, ticket) {
                    DataFormat = Options.RefreshTokenFormat
                };

                // Sets the default refresh token serializer.
                notification.Serializer = payload => {
                    return Task.FromResult(notification.DataFormat?.Protect(payload));
                };

                await Options.Provider.CreateRefreshToken(notification);

                // Treat a non-null refresh token like an implicit HandleResponse call.
                if (notification.HandledResponse || !string.IsNullOrEmpty(notification.RefreshToken)) {
                    return notification.RefreshToken;
                }

                else if (notification.Skipped) {
                    return null;
                }

                // Allow the application to change the authentication
                // ticket from the CreateRefreshTokenAsync event.
                ticket = notification.AuthenticationTicket;
                ticket.Properties.CopyTo(properties);

                return await notification.SerializeTicketAsync();
            }

            catch (Exception exception) {
                Options.Logger.WriteWarning("An exception occured when serializing a refresh token.", exception);

                return null;
            }
        }

        private async Task<AuthenticationTicket> ReceiveAuthorizationCodeAsync(string code, OpenIdConnectMessage request) {
            try {
                var notification = new ReceiveAuthorizationCodeContext(Context, Options, request, code) {
                    DataFormat = Options.AuthorizationCodeFormat
                };

                // Sets the default deserializer used to resolve the
                // authentication ticket corresponding to the authorization code.
                notification.Deserializer = payload => {
                    return Task.FromResult(notification.DataFormat?.Unprotect(payload));
                };

                await Options.Provider.ReceiveAuthorizationCode(notification);

                // Directly return the authentication ticket if one
                // has been provided by ReceiveAuthorizationCode.
                // Treat a non-null ticket like an implicit HandleResponse call.
                if (notification.HandledResponse || notification.AuthenticationTicket != null) {
                    // Ensure the received ticket is an authorization code.
                    if (!string.Equals(notification.AuthenticationTicket.GetUsage(),
                                       OpenIdConnectConstants.Usages.Code, StringComparison.Ordinal)) {
                        Options.Logger.WriteVerbose($"The received token was not an authorization code: {code}.");

                        return null;
                    }

                    return notification.AuthenticationTicket;
                }

                else if (notification.Skipped) {
                    return null;
                }

                var value = (string) Options.Cache.Get(code);
                if (string.IsNullOrEmpty(value)) {
                    return null;
                }

                // Because authorization codes are guaranteed to be unique, make sure
                // to remove the current code from the global store before using it.
                Options.Cache.Remove(code);

                var ticket = await notification.DeserializeTicketAsync(value);

                // Ensure the received ticket is an authorization code.
                if (!string.Equals(ticket.GetUsage(), OpenIdConnectConstants.Usages.Code, StringComparison.Ordinal)) {
                    Options.Logger.WriteVerbose($"The received token was not an authorization code: {code}.");

                    return null;
                }

                return ticket;
            }

            catch (Exception exception) {
                Options.Logger.WriteWarning("An exception occured when deserializing an authorization code.", exception);

                return null;
            }
        }

        private async Task<AuthenticationTicket> ReceiveAccessTokenAsync(string token, OpenIdConnectMessage request) {
            try {
                var notification = new ReceiveAccessTokenContext(Context, Options, request, token) {
                    DataFormat = Options.AccessTokenFormat,
                    Issuer = Context.GetIssuer(Options),
                    SecurityTokenHandler = Options.AccessTokenHandler,
                    SignatureProvider = Options.SignatureProvider,
                    SigningKey = Options.SigningCredentials.Select(credentials => credentials.SigningKey)
                                                           .FirstOrDefault()
                };

                // Sets the default deserializer used to resolve the
                // authentication ticket corresponding to the access token.
                notification.Deserializer = payload => {
                    var handler = notification.SecurityTokenHandler as ISecurityTokenValidator;
                    if (handler == null) {
                        return Task.FromResult(notification.DataFormat?.Unprotect(payload));
                    }

                    // Create new validation parameters to validate the security token.
                    // ValidateAudience and ValidateLifetime are always set to false:
                    // if necessary, the audience and the expiration can be validated
                    // in InvokeValidationEndpointAsync or InvokeTokenEndpointAsync.
                    var parameters = new TokenValidationParameters {
                        IssuerSigningKey = notification.SigningKey,
                        ValidIssuer = notification.Issuer,
                        ValidateAudience = false,
                        ValidateLifetime = false
                    };

                    SecurityToken securityToken;
                    var principal = handler.ValidateToken(payload, parameters, out securityToken);

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

                    var usage = principal.FindFirst(OpenIdConnectConstants.Extra.Usage);
                    if (usage != null) {
                        properties.SetUsage(usage.Value);
                    }

                    return Task.FromResult(new AuthenticationTicket((ClaimsIdentity) principal.Identity, properties));
                };

                await Options.Provider.ReceiveAccessToken(notification);

                // Directly return the authentication ticket if one
                // has been provided by ReceiveAccessToken.
                // Treat a non-null ticket like an implicit HandleResponse call.
                if (notification.HandledResponse || notification.AuthenticationTicket != null) {
                    // Ensure the received ticket is an access token.
                    if (!string.Equals(notification.AuthenticationTicket.GetUsage(),
                                       OpenIdConnectConstants.Usages.AccessToken, StringComparison.Ordinal)) {
                        Options.Logger.WriteVerbose($"The received token was not an access token: {token}.");

                        return null;
                    }

                    return notification.AuthenticationTicket;
                }

                else if (notification.Skipped) {
                    return null;
                }

                var ticket = await notification.DeserializeTicketAsync(token);

                // Ensure the received ticket is an access token.
                if (!string.Equals(ticket.GetUsage(), OpenIdConnectConstants.Usages.AccessToken, StringComparison.Ordinal)) {
                    Options.Logger.WriteVerbose($"The received token was not an access token: {token}.");

                    return null;
                }

                return ticket;
            }

            catch (Exception exception) {
                Options.Logger.WriteWarning("An exception occured when deserializing an access token.", exception);

                return null;
            }
        }

        private async Task<AuthenticationTicket> ReceiveIdentityTokenAsync(string token, OpenIdConnectMessage request) {
            try {
                var notification = new ReceiveIdentityTokenContext(Context, Options, request, token) {
                    Issuer = Context.GetIssuer(Options),
                    SecurityTokenHandler = Options.IdentityTokenHandler,
                    SignatureProvider = Options.SignatureProvider,
                    SigningKey = Options.SigningCredentials.Select(credentials => credentials.SigningKey)
                                                           .FirstOrDefault()
                };

                // Sets the default deserializer used to resolve the
                // authentication ticket corresponding to the identity token.
                notification.Deserializer = payload => {
                    if (notification.SecurityTokenHandler == null) {
                        return Task.FromResult<AuthenticationTicket>(null);
                    }

                    // Create new validation parameters to validate the security token.
                    // ValidateAudience and ValidateLifetime are always set to false:
                    // if necessary, the audience and the expiration can be validated
                    // in InvokeValidationEndpointAsync or InvokeTokenEndpointAsync.
                    var parameters = new TokenValidationParameters {
                        IssuerSigningKey = notification.SigningKey,
                        ValidIssuer = notification.Issuer,
                        ValidateAudience = false,
                        ValidateLifetime = false
                    };

                    SecurityToken securityToken;
                    var principal = notification.SecurityTokenHandler.ValidateToken(payload, parameters, out securityToken);

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

                    var usage = principal.FindFirst(OpenIdConnectConstants.Extra.Usage);
                    if (usage != null) {
                        properties.SetUsage(usage.Value);
                    }

                    return Task.FromResult(new AuthenticationTicket((ClaimsIdentity) principal.Identity, properties));
                };

                await Options.Provider.ReceiveIdentityToken(notification);

                // Directly return the authentication ticket if one
                // has been provided by ReceiveIdentityToken.
                // Treat a non-null ticket like an implicit HandleResponse call.
                if (notification.HandledResponse || notification.AuthenticationTicket != null) {
                    // Ensure the received ticket is an identity token.
                    if (!string.Equals(notification.AuthenticationTicket.GetUsage(),
                                       OpenIdConnectConstants.Usages.IdToken, StringComparison.Ordinal)) {
                        Options.Logger.WriteVerbose($"The received token was not an identity token: {token}.");

                        return null;
                    }

                    return notification.AuthenticationTicket;
                }

                else if (notification.Skipped) {
                    return null;
                }

                var ticket = await notification.DeserializeTicketAsync(token);

                // Ensure the received ticket is an identity token.
                if (!string.Equals(ticket.GetUsage(), OpenIdConnectConstants.Usages.IdToken, StringComparison.Ordinal)) {
                    Options.Logger.WriteVerbose($"The received token was not an identity token: {token}.");

                    return null;
                }

                return ticket;
            }

            catch (Exception exception) {
                Options.Logger.WriteWarning("An exception occured when deserializing an identity token.", exception);

                return null;
            }
        }

        private async Task<AuthenticationTicket> ReceiveRefreshTokenAsync(string token, OpenIdConnectMessage request) {
            try {
                var notification = new ReceiveRefreshTokenContext(Context, Options, request, token) {
                    DataFormat = Options.RefreshTokenFormat
                };

                // Sets the default deserializer used to resolve the
                // authentication ticket corresponding to the refresh token.
                notification.Deserializer = payload => {
                    return Task.FromResult(notification.DataFormat?.Unprotect(payload));
                };

                await Options.Provider.ReceiveRefreshToken(notification);

                // Directly return the authentication ticket if one
                // has been provided by ReceiveRefreshToken.
                // Treat a non-null ticket like an implicit HandleResponse call.
                if (notification.HandledResponse || notification.AuthenticationTicket != null) {
                    // Ensure the received ticket is an identity token.
                    if (!string.Equals(notification.AuthenticationTicket.GetUsage(),
                                       OpenIdConnectConstants.Usages.IdToken, StringComparison.Ordinal)) {
                        Options.Logger.WriteVerbose($"The received token was not a refresh token: {token}.");

                        return null;
                    }

                    return notification.AuthenticationTicket;
                }

                else if (notification.Skipped) {
                    return null;
                }

                var ticket = await notification.DeserializeTicketAsync(token);

                // Ensure the received ticket is an identity token.
                if (!string.Equals(ticket.GetUsage(), OpenIdConnectConstants.Usages.IdToken, StringComparison.Ordinal)) {
                    Options.Logger.WriteVerbose($"The received token was not a refresh token: {token}.");

                    return null;
                }

                return ticket;
            }

            catch (Exception exception) {
                Options.Logger.WriteWarning("An exception occured when deserializing a refresh token.", exception);

                return null;
            }
        }
    }
}
