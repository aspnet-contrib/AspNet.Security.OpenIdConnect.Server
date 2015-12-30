/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using System.Xml;
using AspNet.Security.OpenIdConnect.Extensions;
using Microsoft.AspNet.Authentication;
using Microsoft.AspNet.Http.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace AspNet.Security.OpenIdConnect.Server {
    internal partial class OpenIdConnectServerHandler : AuthenticationHandler<OpenIdConnectServerOptions> {
        private async Task<string> SerializeAuthorizationCodeAsync(
            ClaimsPrincipal principal, AuthenticationProperties properties,
            OpenIdConnectMessage request, OpenIdConnectMessage response) {
            // properties.IssuedUtc and properties.ExpiresUtc
            // should always be preferred when explicitly set.
            if (properties.IssuedUtc == null) {
                properties.IssuedUtc = Options.SystemClock.UtcNow;
            }

            if (properties.ExpiresUtc == null) {
                properties.ExpiresUtc = properties.IssuedUtc + Options.AuthorizationCodeLifetime;
            }

            // Claims in authorization codes are never filtered as they are supposed to be opaque:
            // SerializeAccessTokenAsync and SerializeIdentityTokenAsync are responsible of ensuring
            // that subsequent access and identity tokens are correctly filtered.
            var ticket = new AuthenticationTicket(principal, properties, Options.AuthenticationScheme);
            ticket.SetUsage(OpenIdConnectConstants.Usages.Code);

            // By default, add the client_id to the list of the
            // presenters allowed to use the authorization code.
            if (!string.IsNullOrEmpty(request.ClientId)) {
                ticket.SetPresenters(request.ClientId);
            }

            var notification = new SerializeAuthorizationCodeContext(Context, Options, request, response, ticket) {
                DataFormat = Options.AuthorizationCodeFormat
            };

            await Options.Provider.SerializeAuthorizationCode(notification);

            if (!string.IsNullOrEmpty(notification.AuthorizationCode)) {
                return notification.AuthorizationCode;
            }

            // Allow the application to change the authentication
            // ticket from the SerializeAuthorizationCode event.
            ticket = notification.AuthenticationTicket;
            ticket.Properties.CopyTo(properties);

            if (notification.DataFormat == null) {
                return null;
            }

            var key = Options.RandomNumberGenerator.GenerateKey(length: 256 / 8);

            using (var stream = new MemoryStream())
            using (var writter = new StreamWriter(stream)) {
                writter.Write(notification.DataFormat.Protect(ticket));
                writter.Flush();

                await Options.Cache.SetAsync(key, options => {
                    options.AbsoluteExpiration = ticket.Properties.ExpiresUtc;

                    return stream.ToArray();
                });
            }

            return key;
        }

        private async Task<string> SerializeAccessTokenAsync(
            ClaimsPrincipal principal, AuthenticationProperties properties,
            OpenIdConnectMessage request, OpenIdConnectMessage response) {
            // properties.IssuedUtc and properties.ExpiresUtc
            // should always be preferred when explicitly set.
            if (properties.IssuedUtc == null) {
                properties.IssuedUtc = Options.SystemClock.UtcNow;
            }

            if (properties.ExpiresUtc == null) {
                properties.ExpiresUtc = properties.IssuedUtc + Options.AccessTokenLifetime;
            }

            // Create a new principal containing only the filtered claims.
            // Actors identities are also filtered (delegation scenarios).
            principal = principal.Clone(claim => {
                // Never exclude ClaimTypes.NameIdentifier.
                if (string.Equals(claim.Type, ClaimTypes.NameIdentifier, StringComparison.OrdinalIgnoreCase)) {
                    return true;
                }

                // Claims whose destination is not explicitly referenced or
                // doesn't contain "token" are not included in the access token.
                return claim.HasDestination(OpenIdConnectConstants.ResponseTypes.Token);
            });

            var identity = (ClaimsIdentity) principal.Identity;

            // Create a new ticket containing the updated properties and the filtered principal.
            var ticket = new AuthenticationTicket(principal, properties, Options.AuthenticationScheme);
            ticket.SetUsage(OpenIdConnectConstants.Usages.AccessToken);

            // By default, add the client_id to the list of the
            // presenters allowed to use the access token.
            if (!string.IsNullOrEmpty(request.ClientId)) {
                ticket.SetPresenters(request.ClientId);
            }

            var notification = new SerializeAccessTokenContext(Context, Options, request, response, ticket) {
                DataFormat = Options.AccessTokenFormat,
                Issuer = Context.GetIssuer(Options),
                SecurityTokenHandler = Options.AccessTokenHandler,
                SigningCredentials = Options.SigningCredentials.FirstOrDefault()
            };

            await Options.Provider.SerializeAccessToken(notification);

            if (!string.IsNullOrEmpty(notification.AccessToken)) {
                return notification.AccessToken;
            }

            // Allow the application to change the authentication
            // ticket from the SerializeAccessTokenAsync event.
            ticket = notification.AuthenticationTicket;
            ticket.Properties.CopyTo(properties);

            if (notification.SecurityTokenHandler == null) {
                return notification.DataFormat?.Protect(ticket);
            }

            // Extract the main identity from the principal.
            identity = (ClaimsIdentity) ticket.Principal.Identity;

            // Store the "usage" property as a claim.
            identity.AddClaim(OpenIdConnectConstants.Properties.Usage, ticket.GetUsage());

            // If the ticket is marked as confidential, add a new
            // "confidential" claim in the security token.
            if (ticket.IsConfidential()) {
                identity.AddClaim(new Claim(OpenIdConnectConstants.Properties.Confidential, "true", ClaimValueTypes.Boolean));
            }

            // Create a new claim per scope item, that will result
            // in a "scope" array being added in the access token.
            foreach (var scope in ticket.GetScopes()) {
                identity.AddClaim(OpenIdConnectConstants.Claims.Scope, scope);
            }

            var handler = notification.SecurityTokenHandler as JwtSecurityTokenHandler;
            if (handler != null) {
                // Remove the ClaimTypes.NameIdentifier claims to avoid getting duplicate claims.
                // Note: the "sub" claim is automatically mapped by JwtSecurityTokenHandler
                // to ClaimTypes.NameIdentifier when validating a JWT token.
                // Note: make sure to call ToArray() to avoid an InvalidOperationException
                // on old versions of Mono, where FindAll() is implemented using an iterator.
                foreach (var claim in identity.FindAll(ClaimTypes.NameIdentifier).ToArray()) {
                    identity.RemoveClaim(claim);
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
                foreach (var audience in ticket.GetAudiences()) {
                    identity.AddClaim(JwtRegisteredClaimNames.Aud, audience);
                }

                // Extract the presenters from the authentication ticket.
                var presenters = ticket.GetPresenters().ToArray();

                switch (presenters.Length) {
                    case 0: break;

                    case 1:
                        identity.AddClaim(JwtRegisteredClaimNames.Azp, presenters[0]);
                        break;

                    default:
                        Logger.LogWarning("Multiple presenters have been associated with the access token " +
                                          "but the JWT format only accepts single values.");

                        // Only add the first authorized party.
                        identity.AddClaim(JwtRegisteredClaimNames.Azp, presenters[0]);
                        break;
                }

                var token = handler.CreateToken(
                    subject: identity,
                    issuer: notification.Issuer,
                    signingCredentials: notification.SigningCredentials,
                    issuedAt: ticket.Properties.IssuedUtc.Value.UtcDateTime,
                    notBefore: ticket.Properties.IssuedUtc.Value.UtcDateTime,
                    expires: ticket.Properties.ExpiresUtc.Value.UtcDateTime);

                if (notification.SigningCredentials != null) {
                    var x509SecurityKey = notification.SigningCredentials.Key as X509SecurityKey;
                    if (x509SecurityKey != null) {
                        // Note: unlike "kid", "x5t" is not automatically added by JwtHeader's constructor in IdentityModel for ASP.NET 5.
                        // Though not required by the specifications, this property is needed for IdentityModel for Katana to work correctly.
                        // See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server/issues/132
                        // and https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/issues/181.
                        token.Header[JwtHeaderParameterNames.X5t] = Base64UrlEncoder.Encode(x509SecurityKey.Certificate.GetCertHash());
                    }

                    object identifier;
                    if (!token.Header.TryGetValue(JwtHeaderParameterNames.Kid, out identifier) || identifier == null) {
                        // When the token doesn't contain a "kid" parameter in the header, automatically
                        // add one using the identifier specified in the signing credentials.
                        identifier = notification.SigningCredentials.Kid;

                        if (identifier == null) {
                            // When no key identifier has been explicitly added by the developer, a "kid" is automatically
                            // inferred from the hexadecimal representation of the certificate thumbprint (SHA-1).
                            if (x509SecurityKey != null) {
                                identifier = x509SecurityKey.Certificate.Thumbprint;
                            }

                            // When no key identifier has been explicitly added by the developer, a "kid"
                            // is automatically inferred from the modulus if the signing key is a RSA key.
                            var rsaSecurityKey = notification.SigningCredentials.Key as RsaSecurityKey;
                            if (rsaSecurityKey != null) {
                                // Only use the 40 first chars to match the identifier used by the JWKS endpoint.
                                identifier = Base64UrlEncoder.Encode(rsaSecurityKey.Parameters.Modulus)
                                                             .Substring(0, 40).ToUpperInvariant();
                            }
                        }

                        token.Header[JwtHeaderParameterNames.Kid] = identifier;
                    }
                }

                return handler.WriteToken(token);
            }

            else {
                var token = notification.SecurityTokenHandler.CreateToken(new SecurityTokenDescriptor {
                    Claims = ticket.Principal.Claims,
                    Issuer = notification.Issuer,
                    Audience = notification.Audiences.ElementAtOrDefault(0),
                    SigningCredentials = notification.SigningCredentials,
                    IssuedAt = notification.AuthenticationTicket.Properties.IssuedUtc.Value.UtcDateTime,
                    NotBefore = notification.AuthenticationTicket.Properties.IssuedUtc.Value.UtcDateTime,
                    Expires = notification.AuthenticationTicket.Properties.ExpiresUtc.Value.UtcDateTime
                });

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
            ClaimsPrincipal principal, AuthenticationProperties properties,
            OpenIdConnectMessage request, OpenIdConnectMessage response) {
            // properties.IssuedUtc and properties.ExpiresUtc
            // should always be preferred when explicitly set.
            if (properties.IssuedUtc == null) {
                properties.IssuedUtc = Options.SystemClock.UtcNow;
            }

            if (properties.ExpiresUtc == null) {
                properties.ExpiresUtc = properties.IssuedUtc + Options.IdentityTokenLifetime;
            }

            // Replace the principal by a new one containing only the filtered claims.
            // Actors identities are also filtered (delegation scenarios).
            principal = principal.Clone(claim => {
                // Never exclude ClaimTypes.NameIdentifier.
                if (string.Equals(claim.Type, ClaimTypes.NameIdentifier, StringComparison.OrdinalIgnoreCase)) {
                    return true;
                }

                // Claims whose destination is not explicitly referenced or
                // doesn't contain "id_token" are not included in the identity token.
                return claim.HasDestination(OpenIdConnectConstants.ResponseTypes.IdToken);
            });

            var identity = (ClaimsIdentity) principal.Identity;

            // Create a new ticket containing the updated properties and the filtered principal.
            var ticket = new AuthenticationTicket(principal, properties, Options.AuthenticationScheme);
            ticket.SetUsage(OpenIdConnectConstants.Usages.IdToken);

            // By default, add the client_id to the list of the
            // presenters allowed to use the identity token.
            if (!string.IsNullOrEmpty(request.ClientId)) {
                ticket.SetAudiences(request.ClientId);
                ticket.SetPresenters(request.ClientId);
            }

            var notification = new SerializeIdentityTokenContext(Context, Options, request, response, ticket) {
                Issuer = Context.GetIssuer(Options),
                SecurityTokenHandler = Options.IdentityTokenHandler,
                SigningCredentials = Options.SigningCredentials.FirstOrDefault()
            };

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

            if (!identity.HasClaim(claim => claim.Type == JwtRegisteredClaimNames.Sub) &&
                !identity.HasClaim(claim => claim.Type == ClaimTypes.NameIdentifier)) {
                Logger.LogError("A unique identifier cannot be found to generate a 'sub' claim: " +
                                "make sure to add a 'ClaimTypes.NameIdentifier' claim.");

                return null;
            }

            // Extract the main identity from the principal.
            identity = (ClaimsIdentity) ticket.Principal.Identity;

            // Store the unique subject identifier as a claim.
            if (!identity.HasClaim(claim => claim.Type == JwtRegisteredClaimNames.Sub)) {
                identity.AddClaim(JwtRegisteredClaimNames.Sub, identity.GetClaim(ClaimTypes.NameIdentifier));
            }

            // Remove the ClaimTypes.NameIdentifier claims to avoid getting duplicate claims.
            // Note: the "sub" claim is automatically mapped by JwtSecurityTokenHandler
            // to ClaimTypes.NameIdentifier when validating a JWT token.
            // Note: make sure to call ToArray() to avoid an InvalidOperationException
            // on old versions of Mono, where FindAll() is implemented using an iterator.
            foreach (var claim in identity.FindAll(ClaimTypes.NameIdentifier).ToArray()) {
                identity.RemoveClaim(claim);
            }

            // Store the "usage" property as a claim.
            identity.AddClaim(OpenIdConnectConstants.Properties.Usage, ticket.GetUsage());

            // If the ticket is marked as confidential, add a new
            // "confidential" claim in the security token.
            if (ticket.IsConfidential()) {
                identity.AddClaim(new Claim(OpenIdConnectConstants.Properties.Confidential, "true", ClaimValueTypes.Boolean));
            }

            // Store the audiences as claims.
            foreach (var audience in ticket.GetAudiences()) {
                identity.AddClaim(JwtRegisteredClaimNames.Aud, audience);
            }

            // If a nonce was present in the authorization request, it MUST
            // be included in the id_token generated by the token endpoint.
            // See http://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
            var nonce = request.Nonce;
            if (request.IsAuthorizationCodeGrantType()) {
                // Restore the nonce stored in the authentication
                // ticket extracted from the authorization code.
                nonce = ticket.GetNonce();
            }

            if (!string.IsNullOrEmpty(nonce)) {
                identity.AddClaim(JwtRegisteredClaimNames.Nonce, nonce);
            }

            if (!string.IsNullOrEmpty(response.Code)) {
                using (var algorithm = OpenIdConnectServerHelpers.GetHashAlgorithm(notification.SigningCredentials.Algorithm)) {
                    // Create the c_hash using the authorization code returned by SerializeAuthorizationCodeAsync.
                    var hash = algorithm.ComputeHash(Encoding.ASCII.GetBytes(response.Code));

                    // Note: only the left-most half of the hash of the octets is used.
                    // See http://openid.net/specs/openid-connect-core-1_0.html#HybridIDToken
                    identity.AddClaim(JwtRegisteredClaimNames.CHash, Base64UrlEncoder.Encode(hash, 0, hash.Length / 2));
                }
            }

            if (!string.IsNullOrEmpty(response.AccessToken)) {
                using (var algorithm = OpenIdConnectServerHelpers.GetHashAlgorithm(notification.SigningCredentials.Algorithm)) {
                    // Create the at_hash using the access token returned by SerializeAccessTokenAsync.
                    var hash = algorithm.ComputeHash(Encoding.ASCII.GetBytes(response.AccessToken));

                    // Note: only the left-most half of the hash of the octets is used.
                    // See http://openid.net/specs/openid-connect-core-1_0.html#CodeIDToken
                    identity.AddClaim(JwtRegisteredClaimNames.AtHash, Base64UrlEncoder.Encode(hash, 0, hash.Length / 2));
                }
            }

            // Extract the presenters from the authentication ticket.
            var presenters = ticket.GetPresenters().ToArray();

            switch (presenters.Length) {
                case 0: break;

                case 1:
                    identity.AddClaim(JwtRegisteredClaimNames.Azp, presenters[0]);
                    break;

                default:
                    Logger.LogWarning("Multiple presenters have been associated with the identity token " +
                                      "but the JWT format only accepts single values.");

                    // Only add the first authorized party.
                    identity.AddClaim(JwtRegisteredClaimNames.Azp, presenters[0]);
                    break;
            }

            var token = notification.SecurityTokenHandler.CreateToken(
                subject: identity,
                issuer: notification.Issuer,
                signingCredentials: notification.SigningCredentials,
                issuedAt: ticket.Properties.IssuedUtc.Value.UtcDateTime,
                notBefore: ticket.Properties.IssuedUtc.Value.UtcDateTime,
                expires: ticket.Properties.ExpiresUtc.Value.UtcDateTime);

            if (notification.SigningCredentials != null) {
                var x509SecurityKey = notification.SigningCredentials.Key as X509SecurityKey;
                if (x509SecurityKey != null) {
                    // Note: unlike "kid", "x5t" is not automatically added by JwtHeader's constructor in IdentityModel for ASP.NET 5.
                    // Though not required by the specifications, this property is needed for IdentityModel for Katana to work correctly.
                    // See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server/issues/132
                    // and https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/issues/181.
                    token.Header[JwtHeaderParameterNames.X5t] = Base64UrlEncoder.Encode(x509SecurityKey.Certificate.GetCertHash());
                }

                object identifier;
                if (!token.Header.TryGetValue(JwtHeaderParameterNames.Kid, out identifier) || identifier == null) {
                    // When the token doesn't contain a "kid" parameter in the header, automatically
                    // add one using the identifier specified in the signing credentials.
                    identifier = notification.SigningCredentials.Kid;

                    if (identifier == null) {
                        // When no key identifier has been explicitly added by the developer, a "kid" is automatically
                        // inferred from the hexadecimal representation of the certificate thumbprint (SHA-1).
                        if (x509SecurityKey != null) {
                            identifier = x509SecurityKey.Certificate.Thumbprint;
                        }

                        // When no key identifier has been explicitly added by the developer, a "kid"
                        // is automatically inferred from the modulus if the signing key is a RSA key.
                        var rsaSecurityKey = notification.SigningCredentials.Key as RsaSecurityKey;
                        if (rsaSecurityKey != null) {
                            // Only use the 40 first chars to match the identifier used by the JWKS endpoint.
                            identifier = Base64UrlEncoder.Encode(rsaSecurityKey.Parameters.Modulus)
                                                         .Substring(0, 40).ToUpperInvariant();
                        }
                    }

                    token.Header[JwtHeaderParameterNames.Kid] = identifier;
                }
            }

            return notification.SecurityTokenHandler.WriteToken(token);
        }

        private async Task<string> SerializeRefreshTokenAsync(
            ClaimsPrincipal principal, AuthenticationProperties properties,
            OpenIdConnectMessage request, OpenIdConnectMessage response) {
            // properties.IssuedUtc and properties.ExpiresUtc
            // should always be preferred when explicitly set.
            if (properties.IssuedUtc == null) {
                properties.IssuedUtc = Options.SystemClock.UtcNow;
            }

            if (properties.ExpiresUtc == null) {
                properties.ExpiresUtc = properties.IssuedUtc + Options.RefreshTokenLifetime;
            }

            // Claims in refresh tokens are never filtered as they are supposed to be opaque:
            // SerializeAccessTokenAsync and SerializeIdentityTokenAsync are responsible of ensuring
            // that subsequent access and identity tokens are correctly filtered.
            var ticket = new AuthenticationTicket(principal, properties, Options.AuthenticationScheme);
            ticket.SetUsage(OpenIdConnectConstants.Usages.RefreshToken);

            // By default, add the client_id to the list of the
            // presenters allowed to use the refresh token.
            if (!string.IsNullOrEmpty(request.ClientId)) {
                ticket.SetPresenters(request.ClientId);
            }

            var notification = new SerializeRefreshTokenContext(Context, Options, request, response, ticket) {
                DataFormat = Options.RefreshTokenFormat
            };

            await Options.Provider.SerializeRefreshToken(notification);

            if (!string.IsNullOrEmpty(notification.RefreshToken)) {
                return notification.RefreshToken;
            }

            // Allow the application to change the authentication
            // ticket from the SerializeRefreshTokenAsync event.
            ticket = notification.AuthenticationTicket;
            ticket.Properties.CopyTo(properties);

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

            var buffer = await Options.Cache.GetAsync(code);
            if (buffer == null) {
                return null;
            }

            using (var stream = new MemoryStream(buffer))
            using (var reader = new StreamReader(stream)) {
                // Because authorization codes are guaranteed to be unique, make sure
                // to remove the current code from the global store before using it.
                await Options.Cache.RemoveAsync(code);

                var ticket = notification.DataFormat?.Unprotect(await reader.ReadToEndAsync());
                if (ticket == null) {
                    return null;
                }

                // Ensure the received ticket is an authorization code.
                if (!ticket.IsAuthorizationCode()) {
                    Logger.LogDebug("The received token was not an authorization code: {Code}.", code);

                    return null;
                }

                return ticket;
            }
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
                IssuerSigningKey = notification.SigningCredentials.Key,
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
                Logger.LogDebug("An exception occured when deserializing an identity token: {Message}.", exception.Message);

                return null;
            }

            // Parameters stored in AuthenticationProperties are lost
            // when the identity token is serialized using a security token handler.
            // To mitigate that, they are inferred from the claims or the security token.
            var properties = new AuthenticationProperties {
                ExpiresUtc = securityToken.ValidTo,
                IssuedUtc = securityToken.ValidFrom
            };

            var ticket = new AuthenticationTicket(principal, properties, Options.AuthenticationScheme);

            var audiences = principal.FindAll(JwtRegisteredClaimNames.Aud);
            if (audiences.Any()) {
                ticket.SetAudiences(audiences.Select(claim => claim.Value));
            }

            var presenters = principal.FindAll(JwtRegisteredClaimNames.Azp);
            if (presenters.Any()) {
                ticket.SetPresenters(presenters.Select(claim => claim.Value));
            }

            var scopes = principal.FindAll(OpenIdConnectConstants.Claims.Scope);
            if (scopes.Any()) {
                ticket.SetScopes(scopes.Select(claim => claim.Value));
            }

            var usage = principal.FindFirst(OpenIdConnectConstants.Properties.Usage);
            if (usage != null) {
                ticket.SetUsage(usage.Value);
            }

            var confidential = principal.FindFirst(OpenIdConnectConstants.Properties.Confidential);
            if (confidential != null && string.Equals(confidential.Value, "true", StringComparison.OrdinalIgnoreCase)) {
                ticket.Properties.Items[OpenIdConnectConstants.Properties.Confidential] = "true";
            }

            // Ensure that e received ticket is an access token.
            if (!ticket.IsAccessToken()) {
                Logger.LogDebug("The received token was not an access token: {Token}.", token);

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
                IssuerSigningKey = notification.SigningCredentials.Key,
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
                Logger.LogDebug("An exception occured when deserializing an identity token: {Message}.", exception.Message);

                return null;
            }

            // Parameters stored in AuthenticationProperties are lost
            // when the identity token is serialized using a security token handler.
            // To mitigate that, they are inferred from the claims or the security token.
            var properties = new AuthenticationProperties {
                ExpiresUtc = securityToken.ValidTo,
                IssuedUtc = securityToken.ValidFrom
            };

            var ticket = new AuthenticationTicket(principal, properties, Options.AuthenticationScheme);

            var audiences = principal.FindAll(JwtRegisteredClaimNames.Aud);
            if (audiences.Any()) {
                ticket.SetAudiences(audiences.Select(claim => claim.Value));
            }

            var presenters = principal.FindAll(JwtRegisteredClaimNames.Azp);
            if (presenters.Any()) {
                ticket.SetPresenters(presenters.Select(claim => claim.Value));
            }

            var usage = principal.FindFirst(OpenIdConnectConstants.Properties.Usage);
            if (usage != null) {
                ticket.SetUsage(usage.Value);
            }

            var confidential = principal.FindFirst(OpenIdConnectConstants.Properties.Confidential);
            if (confidential != null && string.Equals(confidential.Value, "true", StringComparison.OrdinalIgnoreCase)) {
                ticket.Properties.Items[OpenIdConnectConstants.Properties.Confidential] = "true";
            }

            // Ensure the received ticket is an identity token.
            if (!ticket.IsIdentityToken()) {
                Logger.LogDebug("The received token was not an identity token: {Token}.", token);

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

            // Ensure the received ticket is a refresh token.
            if (!ticket.IsRefreshToken()) {
                Logger.LogDebug("The received token was not a refresh token: {Token}.", token);

                return null;
            }

            return ticket;
        }
    }
}