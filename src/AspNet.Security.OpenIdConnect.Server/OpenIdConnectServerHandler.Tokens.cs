/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Extensions;
using Microsoft.AspNet.Authentication;
using Microsoft.AspNet.Http.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace AspNet.Security.OpenIdConnect.Server {
    internal partial class OpenIdConnectServerHandler : AuthenticationHandler<OpenIdConnectServerOptions> {
        private async Task<string> CreateAuthorizationCodeAsync(
            ClaimsPrincipal principal, AuthenticationProperties properties,
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
                var ticket = new AuthenticationTicket(principal, properties, Options.AuthenticationScheme);

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

                using (var stream = new MemoryStream())
                using (var writter = new StreamWriter(stream)) {
                    writter.Write(await notification.SerializeTicketAsync());
                    writter.Flush();

                    await Options.Cache.SetAsync(key, options => {
                        options.AbsoluteExpiration = ticket.Properties.ExpiresUtc;

                        return stream.ToArray();
                    });
                }

                return key;
            }

            catch (Exception exception) {
                Logger.LogWarning("An exception occured when serializing an authorization code.", exception);

                return null;
            }
        }

        private async Task<string> CreateAccessTokenAsync(
            ClaimsPrincipal principal, AuthenticationProperties properties,
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

                // Create a new principal containing only the filtered claims.
                // Actors identities are also filtered (delegation scenarios).
                principal = principal.Clone(claim => {
                    // ClaimTypes.NameIdentifier and JwtRegisteredClaimNames.Sub are never excluded.
                    if (string.Equals(claim.Type, ClaimTypes.NameIdentifier, StringComparison.Ordinal) ||
                        string.Equals(claim.Type, JwtRegisteredClaimNames.Sub, StringComparison.Ordinal)) {
                        return true;
                    }

                    // Claims whose destination is not explicitly referenced or
                    // doesn't contain "token" are not included in the access token.
                    return claim.HasDestination(OpenIdConnectConstants.ResponseTypes.Token);
                });

                var identity = (ClaimsIdentity) principal.Identity;

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

                // Create a new ticket containing the updated properties and the filtered principal.
                var ticket = new AuthenticationTicket(principal, properties, Options.AuthenticationScheme);

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

                    // Extract the main identity from the principal.
                    identity = (ClaimsIdentity) payload.Principal.Identity;

                    // Store the "usage" property as a claim.
                    identity.AddClaim(OpenIdConnectConstants.Extra.Usage, payload.Properties.GetUsage());

                    // If the ticket is marked as confidential,
                    // add a new "conf" claim in the JWT token.
                    if (payload.Properties.IsConfidential()) {
                        identity.AddClaim(OpenIdConnectConstants.Extra.Confidential, "true");
                    }

                    // Store the audiences as claims.
                    foreach (var audience in notification.Audiences) {
                        identity.AddClaim(JwtRegisteredClaimNames.Aud, audience);
                    }

                    var token = notification.SecurityTokenHandler.CreateToken(
                        subject: identity,
                        issuer: notification.Issuer,
                        signatureProvider: notification.SignatureProvider,
                        signingCredentials: notification.SigningCredentials,
                        notBefore: payload.Properties.IssuedUtc.Value.UtcDateTime,
                        expires: payload.Properties.ExpiresUtc.Value.UtcDateTime);

                    if (notification.SigningCredentials != null) {
                        var x509SecurityKey = notification.SigningCredentials.SigningKey as X509SecurityKey;
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
                            identifier = notification.SigningCredentials.Kid ?? notification.SigningCredentials.SigningKey.KeyId;

                            if (identifier == null) {
                                // When no key identifier has been explicitly added by the developer, a "kid" is automatically
                                // inferred from the hexadecimal representation of the certificate thumbprint (SHA-1).
                                if (x509SecurityKey != null) {
                                    identifier = x509SecurityKey.Certificate.Thumbprint;
                                }

                                // When no key identifier has been explicitly added by the developer, a "kid"
                                // is automatically inferred from the modulus if the signing key is a RSA key.
                                var rsaSecurityKey = notification.SigningCredentials.SigningKey as RsaSecurityKey;
                                if (rsaSecurityKey != null) {
                                    // Only use the 40 first chars to match the identifier used by the JWKS endpoint.
                                    identifier = Base64UrlEncoder.Encode(rsaSecurityKey.Parameters.Modulus)
                                                                 .Substring(0, 40).ToUpperInvariant();
                                }
                            }

                            token.Header[JwtHeaderParameterNames.Kid] = identifier;
                        }
                    }

                    return Task.FromResult(notification.SecurityTokenHandler.WriteToken(token));
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
                Logger.LogWarning("An exception occured when serializing an access token.", exception);

                return null;
            }
        }

        private async Task<string> CreateIdentityTokenAsync(
            ClaimsPrincipal principal, AuthenticationProperties properties,
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

                // Replace the principal by a new one containing only the filtered claims.
                // Actors identities are also filtered (delegation scenarios).
                principal = principal.Clone(claim => {
                    // ClaimTypes.NameIdentifier and JwtRegisteredClaimNames.Sub are never excluded.
                    if (string.Equals(claim.Type, ClaimTypes.NameIdentifier, StringComparison.Ordinal) ||
                        string.Equals(claim.Type, JwtRegisteredClaimNames.Sub, StringComparison.Ordinal)) {
                        return true;
                    }

                    // Claims whose destination is not explicitly referenced or
                    // doesn't contain "id_token" are not included in the identity token.
                    return claim.HasDestination(OpenIdConnectConstants.ResponseTypes.IdToken);
                });

                var identity = (ClaimsIdentity) principal.Identity;

                identity.AddClaim(JwtRegisteredClaimNames.Iat,
                    EpochTime.GetIntDate(properties.IssuedUtc.Value.UtcDateTime).ToString());

                if (!string.IsNullOrEmpty(response.Code)) {
                    using (var algorithm = SHA256.Create()) {
                        // Create the c_hash using the authorization code returned by CreateAuthorizationCodeAsync.
                        var hash = algorithm.ComputeHash(Encoding.ASCII.GetBytes(response.Code));

                        // Note: only the left-most half of the hash of the octets is used.
                        // See http://openid.net/specs/openid-connect-core-1_0.html#HybridIDToken
                        identity.AddClaim(JwtRegisteredClaimNames.CHash, Base64UrlEncoder.Encode(hash, 0, hash.Length / 2));
                    }
                }

                if (!string.IsNullOrEmpty(response.AccessToken)) {
                    using (var algorithm = SHA256.Create()) {
                        // Create the at_hash using the access token returned by CreateAccessTokenAsync.
                        var hash = algorithm.ComputeHash(Encoding.ASCII.GetBytes(response.AccessToken));

                        // Note: only the left-most half of the hash of the octets is used.
                        // See http://openid.net/specs/openid-connect-core-1_0.html#CodeIDToken
                        identity.AddClaim(JwtRegisteredClaimNames.AtHash, Base64UrlEncoder.Encode(hash, 0, hash.Length / 2));
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
                var subject = principal.FindFirst(JwtRegisteredClaimNames.Sub);
                if (subject == null) {
                    var identifier = principal.FindFirst(ClaimTypes.NameIdentifier);
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

                // Create a new ticket containing the updated properties and the filtered principal.
                var ticket = new AuthenticationTicket(principal, properties, Options.AuthenticationScheme);

                var notification = new CreateIdentityTokenContext(Context, Options, request, response, ticket) {
                    Issuer = Context.GetIssuer(Options),
                    SecurityTokenHandler = Options.IdentityTokenHandler,
                    SignatureProvider = Options.SignatureProvider,
                    SigningCredentials = Options.SigningCredentials.FirstOrDefault()
                };

                // Only add client_id in the audiences list if it is non-null.
                if (!string.IsNullOrEmpty(request.ClientId)) {
                    notification.Audiences.Add(request.ClientId);
                }

                // Sets the default identity token serializer.
                notification.Serializer = payload => {
                    if (notification.SecurityTokenHandler == null) {
                        return Task.FromResult<string>(null);
                    }

                    // Extract the main identity from the principal.
                    identity = (ClaimsIdentity) payload.Principal.Identity;

                    // Store the "usage" property as a claim.
                    identity.AddClaim(OpenIdConnectConstants.Extra.Usage, payload.Properties.GetUsage());

                    // If the ticket is marked as confidential,
                    // add a new "conf" claim in the JWT token.
                    if (payload.Properties.IsConfidential()) {
                        identity.AddClaim(OpenIdConnectConstants.Extra.Confidential, "true");
                    }

                    // Store the audiences as claims.
                    foreach (var audience in notification.Audiences) {
                        identity.AddClaim(JwtRegisteredClaimNames.Aud, audience);
                    }

                    var token = notification.SecurityTokenHandler.CreateToken(
                        subject: identity,
                        issuer: notification.Issuer,
                        signatureProvider: notification.SignatureProvider,
                        signingCredentials: notification.SigningCredentials,
                        notBefore: payload.Properties.IssuedUtc.Value.UtcDateTime,
                        expires: payload.Properties.ExpiresUtc.Value.UtcDateTime);

                    if (notification.SigningCredentials != null) {
                        var x509SecurityKey = notification.SigningCredentials.SigningKey as X509SecurityKey;
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
                            identifier = notification.SigningCredentials.Kid ?? notification.SigningCredentials.SigningKey.KeyId;

                            if (identifier == null) {
                                // When no key identifier has been explicitly added by the developer, a "kid" is automatically
                                // inferred from the hexadecimal representation of the certificate thumbprint (SHA-1).
                                if (x509SecurityKey != null) {
                                    identifier = x509SecurityKey.Certificate.Thumbprint;
                                }

                                // When no key identifier has been explicitly added by the developer, a "kid"
                                // is automatically inferred from the modulus if the signing key is a RSA key.
                                var rsaSecurityKey = notification.SigningCredentials.SigningKey as RsaSecurityKey;
                                if (rsaSecurityKey != null) {
                                    // Only use the 40 first chars to match the identifier used by the JWKS endpoint.
                                    identifier = Base64UrlEncoder.Encode(rsaSecurityKey.Parameters.Modulus)
                                                                 .Substring(0, 40).ToUpperInvariant();
                                }
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
                Logger.LogWarning("An exception occured when serializing an identity token.", exception);

                return null;
            }
        }

        private async Task<string> CreateRefreshTokenAsync(
            ClaimsPrincipal principal, AuthenticationProperties properties,
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
                var ticket = new AuthenticationTicket(principal, properties, Options.AuthenticationScheme);

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
                Logger.LogWarning("An exception occured when serializing a refresh token.", exception);

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
                    if (notification.AuthenticationTicket == null) {
                        return null;
                    }

                    // Ensure the received ticket is an authorization code.
                    if (!notification.AuthenticationTicket.IsAuthorizationCode()) {
                        Logger.LogVerbose("The received token was not an authorization code: {0}.", code);

                        return null;
                    }

                    return notification.AuthenticationTicket;
                }

                else if (notification.Skipped) {
                    return null;
                }

                var buffer = await Options.Cache.GetAsync(code);
                if (buffer == null) {
                    return null;
                }

                using (var stream = new MemoryStream(buffer))
                using (var reader = new StreamReader(stream)) {
                    // Because authorization codes are guaranteed to be unique, make sure
                    // to remove the current code from the global store before using it.
                    await Options.Cache.RemoveAsync(code);

                    var ticket = await notification.DeserializeTicketAsync(await reader.ReadToEndAsync());
                    if (ticket == null) {
                        return null;
                    }

                    // Ensure the received ticket is an authorization code.
                    if (!ticket.IsAuthorizationCode()) {
                        Logger.LogVerbose("The received token was not an authorization code: {0}.", code);

                        return null;
                    }

                    return ticket;
                }
            }

            catch (Exception exception) {
                Logger.LogWarning("An exception occured when deserializing an authorization code.", exception);

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

                    if (principal.Claims.Any(claim => claim.Type == OpenIdConnectConstants.Extra.Confidential)) {
                        properties.Items[OpenIdConnectConstants.Extra.Confidential] = "true";
                    }

                    return Task.FromResult(new AuthenticationTicket(principal, properties, Options.AuthenticationScheme));
                };

                await Options.Provider.ReceiveAccessToken(notification);

                // Directly return the authentication ticket if one
                // has been provided by ReceiveAccessToken.
                // Treat a non-null ticket like an implicit HandleResponse call.
                if (notification.HandledResponse || notification.AuthenticationTicket != null) {
                    if (notification.AuthenticationTicket == null) {
                        return null;
                    }

                    // Ensure the received ticket is an access token.
                    if (!notification.AuthenticationTicket.IsAccessToken()) {
                        Logger.LogVerbose("The received token was not an access token: {0}.", token);

                        return null;
                    }

                    return notification.AuthenticationTicket;
                }

                else if (notification.Skipped) {
                    return null;
                }

                var ticket = await notification.DeserializeTicketAsync(token);
                if (ticket == null) {
                    return null;
                }

                // Ensure the received ticket is an access token.
                if (!ticket.IsAccessToken()) {
                    Logger.LogVerbose("The received token was not an access token: {0}.", token);

                    return null;
                }

                return ticket;
            }

            catch (Exception exception) {
                Logger.LogWarning("An exception occured when deserializing an access token.", exception);

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

                    if (principal.Claims.Any(claim => claim.Type == OpenIdConnectConstants.Extra.Confidential)) {
                        properties.Items[OpenIdConnectConstants.Extra.Confidential] = "true";
                    }

                    return Task.FromResult(new AuthenticationTicket(principal, properties, Options.AuthenticationScheme));
                };

                await Options.Provider.ReceiveIdentityToken(notification);

                // Directly return the authentication ticket if one
                // has been provided by ReceiveIdentityToken.
                // Treat a non-null ticket like an implicit HandleResponse call.
                if (notification.HandledResponse || notification.AuthenticationTicket != null) {
                    if (notification.AuthenticationTicket == null) {
                        return null;
                    }

                    // Ensure the received ticket is an identity token.
                    if (!notification.AuthenticationTicket.IsIdentityToken()) {
                        Logger.LogVerbose("The received token was not an identity token: {0}.", token);

                        return null;
                    }

                    return notification.AuthenticationTicket;
                }

                else if (notification.Skipped) {
                    return null;
                }

                var ticket = await notification.DeserializeTicketAsync(token);
                if (ticket == null) {
                    return null;
                }

                // Ensure the received ticket is an identity token.
                if (!ticket.IsIdentityToken()) {
                    Logger.LogVerbose("The received token was not an identity token: {0}.", token);

                    return null;
                }

                return ticket;
            }

            catch (Exception exception) {
                Logger.LogWarning("An exception occured when deserializing an identity token.", exception);

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
                    if (notification.AuthenticationTicket == null) {
                        return null;
                    }

                    // Ensure the received ticket is a refresh token.
                    if (!notification.AuthenticationTicket.IsRefreshToken()) {
                        Logger.LogVerbose("The received token was not a refresh token: {0}.", token);

                        return null;
                    }

                    return notification.AuthenticationTicket;
                }

                else if (notification.Skipped) {
                    return null;
                }

                var ticket = await notification.DeserializeTicketAsync(token);
                if (ticket == null) {
                    return null;
                }

                // Ensure the received ticket is a refresh token.
                if (!ticket.IsRefreshToken()) {
                    Logger.LogVerbose("The received token was not a refresh token: {0}.", token);

                    return null;
                }

                return ticket;
            }

            catch (Exception exception) {
                Logger.LogWarning("An exception occured when deserializing a refresh token.", exception);

                return null;
            }
        }
    }
}