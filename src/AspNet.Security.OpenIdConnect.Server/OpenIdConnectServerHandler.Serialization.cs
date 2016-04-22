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
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http.Authentication;
using Microsoft.Extensions.Caching.Distributed;
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

            // Associate a random identifier with the authorization code.
            ticket.SetTicketId(Guid.NewGuid().ToString());

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

            if (notification.DataFormat == null) {
                return null;
            }

            // Note: make sure to use a secure generated string having
            // enough entropy to prevent cryptanalytic attacks.
            var key = Options.RandomNumberGenerator.GenerateKey(length: 256 / 8);

            using (var stream = new MemoryStream())
            using (var writter = new StreamWriter(stream)) {
                writter.Write(notification.DataFormat.Protect(ticket));
                writter.Flush();

                // Serialize the authorization code.
                var bytes = stream.ToArray();

                // Store the authorization code in the distributed cache.
                await Options.Cache.SetAsync($"asos-authorization-code:{key}", bytes, new DistributedCacheEntryOptions {
                    AbsoluteExpiration = ticket.Properties.ExpiresUtc
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

                // Claims whose destination is not explicitly referenced or doesn't
                // contain "access_token" are not included in the access token.
                return claim.HasDestination(OpenIdConnectConstants.Destinations.AccessToken);
            });

            var identity = (ClaimsIdentity) principal.Identity;

            // Create a new ticket containing the updated properties and the filtered principal.
            var ticket = new AuthenticationTicket(principal, properties, Options.AuthenticationScheme);
            ticket.SetUsage(OpenIdConnectConstants.Usages.AccessToken);
            ticket.SetAudiences(ticket.GetResources());

            // Associate a random identifier with the access token.
            ticket.SetTicketId(Guid.NewGuid().ToString());

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

            if (notification.SecurityTokenHandler == null) {
                return notification.DataFormat?.Protect(ticket);
            }

            // Extract the main identity from the principal.
            identity = (ClaimsIdentity) ticket.Principal.Identity;

            // Store the "unique_id" property as a claim.
            identity.AddClaim(notification.SecurityTokenHandler is JwtSecurityTokenHandler ?
                OpenIdConnectConstants.Claims.JwtId :
                OpenIdConnectConstants.Claims.TokenId, ticket.GetTicketId());

            // Store the "usage" property as a claim.
            identity.AddClaim(OpenIdConnectConstants.Claims.Usage, ticket.GetUsage());

            // If the ticket is marked as confidential, add a new
            // "confidential" claim in the security token.
            if (ticket.IsConfidential()) {
                identity.AddClaim(new Claim(OpenIdConnectConstants.Claims.Confidential, "true", ClaimValueTypes.Boolean));
            }

            // Create a new claim per scope item, that will result
            // in a "scope" array being added in the access token.
            foreach (var scope in ticket.GetScopes()) {
                identity.AddClaim(OpenIdConnectConstants.Claims.Scope, scope);
            }

            var handler = notification.SecurityTokenHandler as JwtSecurityTokenHandler;
            if (handler != null) {
                // Note: when used as an access token, a JWT token doesn't have to expose a "sub" claim
                // but the name identifier claim is used as a substitute when it has been explicitly added.
                // See https://tools.ietf.org/html/rfc7519#section-4.1.2
                var subject = identity.FindFirst(OpenIdConnectConstants.Claims.Subject);
                if (subject == null) {
                    var identifier = identity.FindFirst(ClaimTypes.NameIdentifier);
                    if (identifier != null) {
                        identity.AddClaim(OpenIdConnectConstants.Claims.Subject, identifier.Value);
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

                // Store the audiences as claims.
                foreach (var audience in ticket.GetAudiences()) {
                    identity.AddClaim(OpenIdConnectConstants.Claims.Audience, audience);
                }

                // Extract the presenters from the authentication ticket.
                var presenters = ticket.GetPresenters().ToArray();

                switch (presenters.Length) {
                    case 0: break;

                    case 1:
                        identity.AddClaim(OpenIdConnectConstants.Claims.AuthorizedParty, presenters[0]);
                        break;

                    default:
                        Logger.LogWarning("Multiple presenters have been associated with the access token " +
                                          "but the JWT format only accepts single values.");

                        // Only add the first authorized party.
                        identity.AddClaim(OpenIdConnectConstants.Claims.AuthorizedParty, presenters[0]);
                        break;
                }

                var token = handler.CreateJwtSecurityToken(
                    subject: identity,
                    issuer: notification.Issuer,
                    signingCredentials: notification.SigningCredentials,
                    issuedAt: ticket.Properties.IssuedUtc.Value.UtcDateTime,
                    notBefore: ticket.Properties.IssuedUtc.Value.UtcDateTime,
                    expires: ticket.Properties.ExpiresUtc.Value.UtcDateTime);

                var x509SecurityKey = notification.SigningCredentials?.Key as X509SecurityKey;
                if (x509SecurityKey != null) {
                    // Note: unlike "kid", "x5t" is not automatically added by JwtHeader's constructor in IdentityModel for .NET Core.
                    // Though not required by the specifications, this property is needed for IdentityModel for Katana to work correctly.
                    // See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server/issues/132
                    // and https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/issues/181.
                    token.Header[JwtHeaderParameterNames.X5t] = Base64UrlEncoder.Encode(x509SecurityKey.Certificate.GetCertHash());
                }

                return handler.WriteToken(token);
            }

            else {
                var token = notification.SecurityTokenHandler.CreateToken(new SecurityTokenDescriptor {
                    Subject = identity,
                    Issuer = notification.Issuer,
                    Audience = notification.Audiences.ElementAtOrDefault(0),
                    SigningCredentials = notification.SigningCredentials,
                    IssuedAt = notification.Ticket.Properties.IssuedUtc.Value.UtcDateTime,
                    NotBefore = notification.Ticket.Properties.IssuedUtc.Value.UtcDateTime,
                    Expires = notification.Ticket.Properties.ExpiresUtc.Value.UtcDateTime
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

                // Claims whose destination is not explicitly referenced or doesn't
                // contain "id_token" are not included in the identity token.
                return claim.HasDestination(OpenIdConnectConstants.Destinations.IdentityToken);
            });

            var identity = (ClaimsIdentity) principal.Identity;

            // Create a new ticket containing the updated properties and the filtered principal.
            var ticket = new AuthenticationTicket(principal, properties, Options.AuthenticationScheme);
            ticket.SetUsage(OpenIdConnectConstants.Usages.IdToken);

            // Associate a random identifier with the identity token.
            ticket.SetTicketId(Guid.NewGuid().ToString());

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

            if (notification.SecurityTokenHandler == null) {
                return null;
            }

            if (!identity.HasClaim(claim => claim.Type == OpenIdConnectConstants.Claims.Subject) &&
                !identity.HasClaim(claim => claim.Type == ClaimTypes.NameIdentifier)) {
                Logger.LogError("A unique identifier cannot be found to generate a 'sub' claim: " +
                                "make sure to add a 'ClaimTypes.NameIdentifier' claim.");

                return null;
            }

            // Extract the main identity from the principal.
            identity = (ClaimsIdentity) ticket.Principal.Identity;

            // Store the unique subject identifier as a claim.
            if (!identity.HasClaim(claim => claim.Type == OpenIdConnectConstants.Claims.Subject)) {
                identity.AddClaim(OpenIdConnectConstants.Claims.Subject, identity.GetClaim(ClaimTypes.NameIdentifier));
            }

            // Remove the ClaimTypes.NameIdentifier claims to avoid getting duplicate claims.
            // Note: the "sub" claim is automatically mapped by JwtSecurityTokenHandler
            // to ClaimTypes.NameIdentifier when validating a JWT token.
            // Note: make sure to call ToArray() to avoid an InvalidOperationException
            // on old versions of Mono, where FindAll() is implemented using an iterator.
            foreach (var claim in identity.FindAll(ClaimTypes.NameIdentifier).ToArray()) {
                identity.RemoveClaim(claim);
            }

            // Store the "unique_id" property as a claim.
            identity.AddClaim(OpenIdConnectConstants.Claims.JwtId, ticket.GetTicketId());

            // Store the "usage" property as a claim.
            identity.AddClaim(OpenIdConnectConstants.Claims.Usage, ticket.GetUsage());

            // If the ticket is marked as confidential, add a new
            // "confidential" claim in the security token.
            if (ticket.IsConfidential()) {
                identity.AddClaim(new Claim(OpenIdConnectConstants.Claims.Confidential, "true", ClaimValueTypes.Boolean));
            }

            // Store the audiences as claims.
            foreach (var audience in ticket.GetAudiences()) {
                identity.AddClaim(OpenIdConnectConstants.Claims.Audience, audience);
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
                identity.AddClaim(OpenIdConnectConstants.Claims.Nonce, nonce);
            }

            if (!string.IsNullOrEmpty(response.Code)) {
                using (var algorithm = OpenIdConnectServerHelpers.GetHashAlgorithm(notification.SigningCredentials.Algorithm)) {
                    // Create the c_hash using the authorization code returned by SerializeAuthorizationCodeAsync.
                    var hash = algorithm.ComputeHash(Encoding.ASCII.GetBytes(response.Code));

                    // Note: only the left-most half of the hash of the octets is used.
                    // See http://openid.net/specs/openid-connect-core-1_0.html#HybridIDToken
                    identity.AddClaim(OpenIdConnectConstants.Claims.CodeHash,
                        Base64UrlEncoder.Encode(hash, 0, hash.Length / 2));
                }
            }

            if (!string.IsNullOrEmpty(response.AccessToken)) {
                using (var algorithm = OpenIdConnectServerHelpers.GetHashAlgorithm(notification.SigningCredentials.Algorithm)) {
                    // Create the at_hash using the access token returned by SerializeAccessTokenAsync.
                    var hash = algorithm.ComputeHash(Encoding.ASCII.GetBytes(response.AccessToken));

                    // Note: only the left-most half of the hash of the octets is used.
                    // See http://openid.net/specs/openid-connect-core-1_0.html#CodeIDToken
                    identity.AddClaim(OpenIdConnectConstants.Claims.AccessTokenHash,
                        Base64UrlEncoder.Encode(hash, 0, hash.Length / 2));
                }
            }

            // Extract the presenters from the authentication ticket.
            var presenters = ticket.GetPresenters().ToArray();

            switch (presenters.Length) {
                case 0: break;

                case 1:
                    identity.AddClaim(OpenIdConnectConstants.Claims.AuthorizedParty, presenters[0]);
                    break;

                default:
                    Logger.LogWarning("Multiple presenters have been associated with the identity token " +
                                      "but the JWT format only accepts single values.");

                    // Only add the first authorized party.
                    identity.AddClaim(OpenIdConnectConstants.Claims.AuthorizedParty, presenters[0]);
                    break;
            }

            var token = notification.SecurityTokenHandler.CreateJwtSecurityToken(
                subject: identity,
                issuer: notification.Issuer,
                signingCredentials: notification.SigningCredentials,
                issuedAt: ticket.Properties.IssuedUtc.Value.UtcDateTime,
                notBefore: ticket.Properties.IssuedUtc.Value.UtcDateTime,
                expires: ticket.Properties.ExpiresUtc.Value.UtcDateTime);

            var x509SecurityKey = notification.SigningCredentials?.Key as X509SecurityKey;
            if (x509SecurityKey != null) {
                // Note: unlike "kid", "x5t" is not automatically added by JwtHeader's constructor in IdentityModel for .NET Core.
                // Though not required by the specifications, this property is needed for IdentityModel for Katana to work correctly.
                // See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server/issues/132
                // and https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/issues/181.
                token.Header[JwtHeaderParameterNames.X5t] = Base64UrlEncoder.Encode(x509SecurityKey.Certificate.GetCertHash());
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

            // Associate a random identifier with the refresh token.
            ticket.SetTicketId(Guid.NewGuid().ToString());

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

            return notification.DataFormat?.Protect(ticket);
        }

        private async Task<AuthenticationTicket> DeserializeAuthorizationCodeAsync(string code, OpenIdConnectMessage request) {
            var notification = new DeserializeAuthorizationCodeContext(Context, Options, request, code) {
                DataFormat = Options.AuthorizationCodeFormat
            };

            await Options.Provider.DeserializeAuthorizationCode(notification);

            // Directly return the authentication ticket if one
            // has been provided by DeserializeAuthorizationCode.
            if (notification.Ticket != null) {
                return notification.Ticket;
            }

            var buffer = await Options.Cache.GetAsync($"asos-authorization-code:{code}");
            if (buffer == null) {
                return null;
            }

            using (var stream = new MemoryStream(buffer))
            using (var reader = new StreamReader(stream)) {
                // Because authorization codes are guaranteed to be unique, make sure
                // to remove the current code from the global store before using it.
                await Options.Cache.RemoveAsync($"asos-authorization-code:{code}");

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
            if (notification.Ticket != null) {
                return notification.Ticket;
            }

            var handler = notification.SecurityTokenHandler as ISecurityTokenValidator;
            if (handler == null) {
                return notification.DataFormat?.Unprotect(token);
            }

            // Create new validation parameters to validate the security token.
            // ValidateAudience and ValidateLifetime are always set to false:
            // if necessary, the audience and the expiration can be validated
            // in InvokeIntrospectionEndpointAsync or InvokeTokenEndpointAsync.
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

            var audiences = principal.FindAll(OpenIdConnectConstants.Claims.Audience);
            if (audiences.Any()) {
                ticket.SetAudiences(audiences.Select(claim => claim.Value));
            }

            var presenters = principal.FindAll(OpenIdConnectConstants.Claims.AuthorizedParty);
            if (presenters.Any()) {
                ticket.SetPresenters(presenters.Select(claim => claim.Value));
            }

            var scopes = principal.FindAll(OpenIdConnectConstants.Claims.Scope);
            if (scopes.Any()) {
                ticket.SetScopes(scopes.Select(claim => claim.Value));
            }

            // Note: the token identifier may be stored in either the token_id claim
            // or in the jti claim, which is the standard name used by JWT tokens.
            var identifier = principal.FindFirst(OpenIdConnectConstants.Claims.JwtId) ??
                             principal.FindFirst(OpenIdConnectConstants.Claims.TokenId);
            if (identifier != null) {
                ticket.SetTicketId(identifier.Value);
            }

            var usage = principal.FindFirst(OpenIdConnectConstants.Claims.Usage);
            if (usage != null) {
                ticket.SetUsage(usage.Value);
            }

            var confidential = principal.FindFirst(OpenIdConnectConstants.Claims.Confidential);
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
            if (notification.Ticket != null) {
                return notification.Ticket;
            }

            if (notification.SecurityTokenHandler == null) {
                return null;
            }

            // Create new validation parameters to validate the security token.
            // ValidateAudience and ValidateLifetime are always set to false:
            // if necessary, the audience and the expiration can be validated
            // in InvokeIntrospectionEndpointAsync or InvokeTokenEndpointAsync.
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

            var audiences = principal.FindAll(OpenIdConnectConstants.Claims.Audience);
            if (audiences.Any()) {
                ticket.SetAudiences(audiences.Select(claim => claim.Value));
            }

            var presenters = principal.FindAll(OpenIdConnectConstants.Claims.AuthorizedParty);
            if (presenters.Any()) {
                ticket.SetPresenters(presenters.Select(claim => claim.Value));
            }

            var identifier = principal.FindFirst(OpenIdConnectConstants.Claims.JwtId);
            if (identifier != null) {
                ticket.SetTicketId(identifier.Value);
            }

            var usage = principal.FindFirst(OpenIdConnectConstants.Claims.Usage);
            if (usage != null) {
                ticket.SetUsage(usage.Value);
            }

            var confidential = principal.FindFirst(OpenIdConnectConstants.Claims.Confidential);
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
            if (notification.Ticket != null) {
                return notification.Ticket;
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