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
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Protocols;
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

            // Claims in authorization codes are never filtered as they are supposed to be opaque:
            // SerializeAccessTokenAsync and SerializeIdentityTokenAsync are responsible of ensuring
            // that subsequent access and identity tokens are correctly filtered.
            var ticket = new AuthenticationTicket(identity, properties);
            ticket.SetUsage(OpenIdConnectConstants.Usages.AuthorizationCode);

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

            if (notification.HandledResponse || !string.IsNullOrEmpty(notification.AuthorizationCode)) {
                return notification.AuthorizationCode;
            }

            else if (notification.Skipped) {
                return null;
            }

            if (notification.DataFormat == null) {
                return null;
            }

            return notification.DataFormat.Protect(ticket);
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

            // Create a new identity containing only the filtered claims.
            // Actors identities are also filtered (delegation scenarios).
            identity = identity.Clone(claim => {
                // Never exclude ClaimTypes.NameIdentifier.
                if (string.Equals(claim.Type, ClaimTypes.NameIdentifier, StringComparison.OrdinalIgnoreCase)) {
                    return true;
                }

                // Claims whose destination is not explicitly referenced or doesn't
                // contain "access_token" are not included in the access token.
                return claim.HasDestination(OpenIdConnectConstants.Destinations.AccessToken);
            });

            // Create a new ticket containing the updated properties and the filtered identity.
            var ticket = new AuthenticationTicket(identity, properties);
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

            if (notification.HandledResponse || !string.IsNullOrEmpty(notification.AccessToken)) {
                return notification.AccessToken;
            }

            else if (notification.Skipped) {
                return null;
            }

            if (!notification.Audiences.Any()) {
                Options.Logger.LogInformation("No explicit audience was associated with the access token.");
            }

            if (notification.SecurityTokenHandler == null) {
                return notification.DataFormat?.Protect(ticket);
            }

            if (notification.SigningCredentials == null) {
                throw new InvalidOperationException("A signing key must be provided.");
            }

            // Store the "unique_id" property as a claim.
            ticket.Identity.AddClaim(notification.SecurityTokenHandler is JwtSecurityTokenHandler ?
                OpenIdConnectConstants.Claims.JwtId :
                OpenIdConnectConstants.Claims.TokenId, ticket.GetTicketId());

            // Store the "usage" property as a claim.
            ticket.Identity.AddClaim(OpenIdConnectConstants.Claims.Usage, ticket.GetUsage());

            // If the ticket is marked as confidential, add a new
            // "confidential" claim in the security token.
            if (ticket.IsConfidential()) {
                ticket.Identity.AddClaim(new Claim(OpenIdConnectConstants.Claims.Confidential, "true", ClaimValueTypes.Boolean));
            }

            // Create a new claim per scope item, that will result
            // in a "scope" array being added in the access token.
            foreach (var scope in notification.Scopes) {
                ticket.Identity.AddClaim(OpenIdConnectConstants.Claims.Scope, scope);
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
                foreach (var claim in ticket.Identity.FindAll(ClaimTypes.NameIdentifier).ToArray()) {
                    ticket.Identity.RemoveClaim(claim);
                }

                // Store the audiences as claims.
                foreach (var audience in notification.Audiences) {
                    ticket.Identity.AddClaim(OpenIdConnectConstants.Claims.Audience, audience);
                }

                // Extract the presenters from the authentication ticket.
                var presenters = notification.Presenters.ToArray();
                switch (presenters.Length) {
                    case 0: break;

                    case 1:
                        identity.AddClaim(OpenIdConnectConstants.Claims.AuthorizedParty, presenters[0]);
                        break;

                    default:
                        Options.Logger.LogWarning("Multiple presenters have been associated with the access token " +
                                                  "but the JWT format only accepts single values.");

                        // Only add the first authorized party.
                        identity.AddClaim(OpenIdConnectConstants.Claims.AuthorizedParty, presenters[0]);
                        break;
                }

                var token = handler.CreateToken(
                    subject: ticket.Identity,
                    issuer: notification.Issuer,
                    signingCredentials: notification.SigningCredentials,
                    notBefore: ticket.Properties.IssuedUtc.Value.UtcDateTime,
                    expires: ticket.Properties.ExpiresUtc.Value.UtcDateTime);

                token.Payload[OpenIdConnectConstants.Claims.IssuedAt] =
                    EpochTime.GetIntDate(ticket.Properties.IssuedUtc.Value.UtcDateTime);

                // Try to extract a key identifier from the signing credentials
                // and add the "kid" property to the JWT header if applicable.
                LocalIdKeyIdentifierClause clause = null;
                if (notification.SigningCredentials.SigningKeyIdentifier.TryFind(out clause)) {
                    token.Header[JwtHeaderParameterNames.Kid] = clause.LocalId;
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
                        notification.Ticket.Properties.IssuedUtc.Value.UtcDateTime,
                        notification.Ticket.Properties.ExpiresUtc.Value.UtcDateTime)
                };

                // When the encrypting credentials use an asymmetric key, replace them by a
                // EncryptedKeyEncryptingCredentials instance to generate a symmetric key.
                if (descriptor.EncryptingCredentials?.SecurityKey is AsymmetricSecurityKey) {
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

            // Replace the identity by a new one containing only the filtered claims.
            // Actors identities are also filtered (delegation scenarios).
            identity = identity.Clone(claim => {
                // Never exclude ClaimTypes.NameIdentifier.
                if (string.Equals(claim.Type, ClaimTypes.NameIdentifier, StringComparison.OrdinalIgnoreCase)) {
                    return true;
                }

                // Claims whose destination is not explicitly referenced or doesn't
                // contain "id_token" are not included in the identity token.
                return claim.HasDestination(OpenIdConnectConstants.Destinations.IdentityToken);
            });

            // Create a new ticket containing the updated properties and the filtered identity.
            var ticket = new AuthenticationTicket(identity, properties);
            ticket.SetUsage(OpenIdConnectConstants.Usages.IdentityToken);

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

            if (notification.HandledResponse || !string.IsNullOrEmpty(notification.IdentityToken)) {
                return notification.IdentityToken;
            }

            else if (notification.Skipped) {
                return null;
            }

            if (notification.SecurityTokenHandler == null) {
                return null;
            }

            if (!identity.HasClaim(claim => claim.Type == OpenIdConnectConstants.Claims.Subject) &&
                !identity.HasClaim(claim => claim.Type == ClaimTypes.NameIdentifier)) {
                throw new InvalidOperationException("A unique identifier cannot be found to generate a 'sub' claim: " +
                                                    "make sure to add a 'ClaimTypes.NameIdentifier' claim.");
            }

            if (notification.SigningCredentials == null) {
                throw new InvalidOperationException("A signing key must be provided.");
            }

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
            ticket.Identity.AddClaim(OpenIdConnectConstants.Claims.JwtId, ticket.GetTicketId());

            // Store the "usage" property as a claim.
            ticket.Identity.AddClaim(OpenIdConnectConstants.Claims.Usage, ticket.GetUsage());

            // If the ticket is marked as confidential, add a new
            // "confidential" claim in the security token.
            if (ticket.IsConfidential()) {
                ticket.Identity.AddClaim(new Claim(OpenIdConnectConstants.Claims.Confidential, "true", ClaimValueTypes.Boolean));
            }

            // Store the audiences as claims.
            foreach (var audience in notification.Audiences) {
                ticket.Identity.AddClaim(OpenIdConnectConstants.Claims.Audience, audience);
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
                ticket.Identity.AddClaim(OpenIdConnectConstants.Claims.Nonce, nonce);
            }

            using (var algorithm = HashAlgorithm.Create(notification.SigningCredentials.DigestAlgorithm)) {
                // Create an authorization code hash if necessary.
                if (!string.IsNullOrEmpty(response.Code)) {
                    var hash = algorithm.ComputeHash(Encoding.ASCII.GetBytes(response.Code));

                    // Note: only the left-most half of the hash of the octets is used.
                    // See http://openid.net/specs/openid-connect-core-1_0.html#HybridIDToken
                    identity.AddClaim(OpenIdConnectConstants.Claims.CodeHash, Base64UrlEncoder.Encode(hash, 0, hash.Length / 2));
                }

                // Create an access token hash if necessary.
                if (!string.IsNullOrEmpty(response.AccessToken)) {
                    var hash = algorithm.ComputeHash(Encoding.ASCII.GetBytes(response.AccessToken));

                    // Note: only the left-most half of the hash of the octets is used.
                    // See http://openid.net/specs/openid-connect-core-1_0.html#CodeIDToken
                    identity.AddClaim(OpenIdConnectConstants.Claims.AccessTokenHash, Base64UrlEncoder.Encode(hash, 0, hash.Length / 2));
                }
            }

            // Extract the presenters from the authentication ticket.
            var presenters = notification.Presenters.ToArray();
            switch (presenters.Length) {
                case 0: break;

                case 1:
                    identity.AddClaim(OpenIdConnectConstants.Claims.AuthorizedParty, presenters[0]);
                    break;

                default:
                    Options.Logger.LogWarning("Multiple presenters have been associated with the identity token " +
                                              "but the JWT format only accepts single values.");

                    // Only add the first authorized party.
                    identity.AddClaim(OpenIdConnectConstants.Claims.AuthorizedParty, presenters[0]);
                    break;
            }

            var token = notification.SecurityTokenHandler.CreateToken(
                subject: ticket.Identity,
                issuer: notification.Issuer,
                signingCredentials: notification.SigningCredentials,
                notBefore: ticket.Properties.IssuedUtc.Value.UtcDateTime,
                expires: ticket.Properties.ExpiresUtc.Value.UtcDateTime);

            token.Payload[OpenIdConnectConstants.Claims.IssuedAt] =
                EpochTime.GetIntDate(ticket.Properties.IssuedUtc.Value.UtcDateTime);

            // Try to extract a key identifier from the signing credentials
            // and add the "kid" property to the JWT header if applicable.
            LocalIdKeyIdentifierClause clause = null;
            if (notification.SigningCredentials.SigningKeyIdentifier.TryFind(out clause)) {
                token.Header[JwtHeaderParameterNames.Kid] = clause.LocalId;
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

            // Claims in refresh tokens are never filtered as they are supposed to be opaque:
            // SerializeAccessTokenAsync and SerializeIdentityTokenAsync are responsible of ensuring
            // that subsequent access and identity tokens are correctly filtered.
            var ticket = new AuthenticationTicket(identity, properties);
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

            if (notification.HandledResponse || !string.IsNullOrEmpty(notification.RefreshToken)) {
                return notification.RefreshToken;
            }

            else if (notification.Skipped) {
                return null;
            }

            return notification.DataFormat?.Protect(ticket);
        }

        private async Task<AuthenticationTicket> DeserializeAuthorizationCodeAsync(string code, OpenIdConnectMessage request) {
            var notification = new DeserializeAuthorizationCodeContext(Context, Options, request, code) {
                DataFormat = Options.AuthorizationCodeFormat
            };

            await Options.Provider.DeserializeAuthorizationCode(notification);

            if (notification.HandledResponse || notification.Ticket != null) {
                return notification.Ticket;
            }

            else if (notification.Skipped) {
                return null;
            }

            var ticket = notification.DataFormat?.Unprotect(code);
            if (ticket == null) {
                return null;
            }

            // Ensure the received ticket is an authorization code.
            if (!ticket.IsAuthorizationCode()) {
                Options.Logger.LogDebug("The received token was not an authorization code: {Code}.", code);

                return null;
            }

            return ticket;
        }

        private async Task<AuthenticationTicket> DeserializeAccessTokenAsync(string token, OpenIdConnectMessage request) {
            var notification = new DeserializeAccessTokenContext(Context, Options, request, token) {
                DataFormat = Options.AccessTokenFormat,
                SecurityTokenHandler = Options.AccessTokenHandler
            };

            // Note: ValidateAudience and ValidateLifetime are always set to false:
            // if necessary, the audience and the expiration can be validated
            // in InvokeIntrospectionEndpointAsync or InvokeTokenEndpointAsync.
            notification.TokenValidationParameters = new TokenValidationParameters {
                IssuerSigningKeys = Options.SigningCredentials.Select(credentials => credentials.SigningKey),
                ValidIssuer = Context.GetIssuer(Options),
                ValidateAudience = false,
                ValidateLifetime = false
            };

            if (notification.SecurityTokenHandler is JwtSecurityTokenHandler) {
                notification.TokenValidationParameters.IssuerSigningTokens =
                    from credentials in Options.SigningCredentials
                    where credentials.SigningKeyIdentifier != null
                    from clause in credentials.SigningKeyIdentifier.OfType<LocalIdKeyIdentifierClause>()
                    select new NamedKeySecurityToken(OpenIdConnectConstants.Claims.KeyId, clause.LocalId, credentials.SigningKey);
            }

            await Options.Provider.DeserializeAccessToken(notification);

            if (notification.HandledResponse || notification.Ticket != null) {
                return notification.Ticket;
            }

            else if (notification.Skipped) {
                return null;
            }

            var handler = notification.SecurityTokenHandler as ISecurityTokenValidator;
            if (handler == null) {
                return notification.DataFormat?.Unprotect(token);
            }

            SecurityToken securityToken;
            ClaimsPrincipal principal;

            try {
                if (!handler.CanReadToken(token)) {
                    Options.Logger.LogDebug("The access token handler refused to read the token: {Token}", token);

                    return null;
                }

                principal = handler.ValidateToken(token, notification.TokenValidationParameters, out securityToken);
            }

            catch (Exception exception) {
                Options.Logger.LogDebug("An exception occured when deserializing an access token: {Message}", exception.Message);

                return null;
            }

            // Parameters stored in AuthenticationProperties are lost
            // when the identity token is serialized using a security token handler.
            // To mitigate that, they are inferred from the claims or the security token.
            var properties = new AuthenticationProperties {
                ExpiresUtc = securityToken.ValidTo,
                IssuedUtc = securityToken.ValidFrom
            };

            var ticket = new AuthenticationTicket((ClaimsIdentity) principal.Identity, properties);

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
                ticket.Properties.Dictionary[OpenIdConnectConstants.Properties.Confidential] = "true";
            }

            // Ensure the received ticket is an access token.
            if (!ticket.IsAccessToken()) {
                Options.Logger.LogDebug("The received token was not an access token: {Token}.", token);

                return null;
            }

            return ticket;
        }

        private async Task<AuthenticationTicket> DeserializeIdentityTokenAsync(string token, OpenIdConnectMessage request) {
            var notification = new DeserializeIdentityTokenContext(Context, Options, request, token) {
                SecurityTokenHandler = Options.IdentityTokenHandler
            };

            // Note: ValidateAudience and ValidateLifetime are always set to false:
            // if necessary, the audience and the expiration can be validated
            // in InvokeIntrospectionEndpointAsync or InvokeTokenEndpointAsync.
            notification.TokenValidationParameters = new TokenValidationParameters {
                IssuerSigningKeys = Options.SigningCredentials.Select(credentials => credentials.SigningKey),
                ValidIssuer = Context.GetIssuer(Options),
                ValidateAudience = false,
                ValidateLifetime = false
            };

            if (notification.SecurityTokenHandler is JwtSecurityTokenHandler) {
                notification.TokenValidationParameters.IssuerSigningTokens =
                    from credentials in Options.SigningCredentials
                    where credentials.SigningKeyIdentifier != null
                    from clause in credentials.SigningKeyIdentifier.OfType<LocalIdKeyIdentifierClause>()
                    select new NamedKeySecurityToken(OpenIdConnectConstants.Claims.KeyId, clause.LocalId, credentials.SigningKey);
            }

            await Options.Provider.DeserializeIdentityToken(notification);

            if (notification.HandledResponse || notification.Ticket != null) {
                return notification.Ticket;
            }

            else if (notification.Skipped) {
                return null;
            }

            if (notification.SecurityTokenHandler == null) {
                return null;
            }

            SecurityToken securityToken;
            ClaimsPrincipal principal;

            try {
                if (!notification.SecurityTokenHandler.CanReadToken(token)) {
                    Options.Logger.LogDebug("The identity token handler refused to read the token: {Token}", token);

                    return null;
                }

                principal = notification.SecurityTokenHandler.ValidateToken(token, notification.TokenValidationParameters, out securityToken);
            }

            catch (Exception exception) {
                Options.Logger.LogDebug("An exception occured when deserializing an identity token: {Message}", exception.Message);

                return null;
            }

            // Parameters stored in AuthenticationProperties are lost
            // when the identity token is serialized using a security token handler.
            // To mitigate that, they are inferred from the claims or the security token.
            var properties = new AuthenticationProperties {
                ExpiresUtc = securityToken.ValidTo,
                IssuedUtc = securityToken.ValidFrom
            };

            var ticket = new AuthenticationTicket((ClaimsIdentity) principal.Identity, properties);

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
                ticket.Properties.Dictionary[OpenIdConnectConstants.Properties.Confidential] = "true";
            }

            // Ensure the received ticket is an identity token.
            if (!ticket.IsIdentityToken()) {
                Options.Logger.LogDebug("The received token was not an identity token: {Token}.", token);

                return null;
            }

            return ticket;
        }

        private async Task<AuthenticationTicket> DeserializeRefreshTokenAsync(string token, OpenIdConnectMessage request) {
            var notification = new DeserializeRefreshTokenContext(Context, Options, request, token) {
                DataFormat = Options.RefreshTokenFormat
            };

            await Options.Provider.DeserializeRefreshToken(notification);

            if (notification.HandledResponse || notification.Ticket != null) {
                return notification.Ticket;
            }

            else if (notification.Skipped) {
                return null;
            }

            var ticket = notification.DataFormat?.Unprotect(token);
            if (ticket == null) {
                return null;
            }

            // Ensure the received ticket is an identity token.
            if (!ticket.IsRefreshToken()) {
                Options.Logger.LogDebug("The received token was not a refresh token: {Token}.", token);

                return null;
            }

            return ticket;
        }
    }
}
