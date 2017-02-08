/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Extensions;
using AspNet.Security.OpenIdConnect.Primitives;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;

namespace AspNet.Security.OpenIdConnect.Server {
    internal partial class OpenIdConnectServerHandler : AuthenticationHandler<OpenIdConnectServerOptions> {
        private async Task<string> SerializeAuthorizationCodeAsync(
            ClaimsPrincipal principal, AuthenticationProperties properties,
            OpenIdConnectRequest request, OpenIdConnectResponse response) {
            // Note: claims in authorization codes are never filtered as they are supposed to be opaque:
            // SerializeAccessTokenAsync and SerializeIdentityTokenAsync are responsible of ensuring
            // that subsequent access and identity tokens are correctly filtered.

            // Create a new ticket containing the updated properties.
            var ticket = new AuthenticationTicket(principal, properties, Options.AuthenticationScheme);
            ticket.Properties.IssuedUtc = Options.SystemClock.UtcNow;
            ticket.Properties.ExpiresUtc = ticket.Properties.IssuedUtc +
                (ticket.GetAuthorizationCodeLifetime() ?? Options.AuthorizationCodeLifetime);

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

            if (!ReferenceEquals(ticket, notification.Ticket)) {
                throw new InvalidOperationException("The authentication ticket cannot be replaced.");
            }

            if (notification.DataFormat == null) {
                return null;
            }

            return notification.DataFormat.Protect(ticket);
        }

        private async Task<string> SerializeAccessTokenAsync(
            ClaimsPrincipal principal, AuthenticationProperties properties,
            OpenIdConnectRequest request, OpenIdConnectResponse response) {
            // Create a new principal containing only the filtered claims.
            // Actors identities are also filtered (delegation scenarios).
            principal = principal.Clone(claim => {
                // Never exclude the subject claims.
                if (string.Equals(claim.Type, OpenIdConnectConstants.Claims.Subject, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(claim.Type, ClaimTypes.NameIdentifier, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(claim.Type, ClaimTypes.Upn, StringComparison.OrdinalIgnoreCase)) {
                    return true;
                }

                // Claims whose destination is not explicitly referenced or doesn't
                // contain "access_token" are not included in the access token.
                if (!claim.HasDestination(OpenIdConnectConstants.Destinations.AccessToken)) {
                    Logger.LogDebug("'{Claim}' was excluded from the access token claims.", claim.Type);

                    return false;
                }

                return true;
            });

            var identity = (ClaimsIdentity) principal.Identity;

            // Create a new ticket containing the updated properties and the filtered principal.
            var ticket = new AuthenticationTicket(principal, properties, Options.AuthenticationScheme);
            ticket.Properties.IssuedUtc = Options.SystemClock.UtcNow;
            ticket.Properties.ExpiresUtc = ticket.Properties.IssuedUtc +
                (ticket.GetAccessTokenLifetime() ?? Options.AccessTokenLifetime);

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
                SigningCredentials = Options.SigningCredentials.FirstOrDefault(key => key.Key is SymmetricSecurityKey) ??
                                     Options.SigningCredentials.FirstOrDefault()
            };

            await Options.Provider.SerializeAccessToken(notification);

            if (notification.HandledResponse || !string.IsNullOrEmpty(notification.AccessToken)) {
                return notification.AccessToken;
            }

            else if (notification.Skipped) {
                return null;
            }

            if (!ReferenceEquals(ticket, notification.Ticket)) {
                throw new InvalidOperationException("The authentication ticket cannot be replaced.");
            }

            if (notification.SecurityTokenHandler == null) {
                return notification.DataFormat?.Protect(ticket);
            }

            // At this stage, throw an exception if no signing credentials were provided.
            if (notification.SigningCredentials == null) {
                throw new InvalidOperationException("A signing key must be provided.");
            }

            // Extract the main identity from the principal.
            identity = (ClaimsIdentity) ticket.Principal.Identity;

            // Store the "unique_id" property as a claim.
            identity.AddClaim(OpenIdConnectConstants.Claims.JwtId, ticket.GetTicketId());

            // Store the "usage" property as a claim.
            identity.AddClaim(OpenIdConnectConstants.Claims.Usage, ticket.GetUsage());

            // Store the "confidentiality_level" property as a claim.
            var confidentiality = ticket.GetProperty(OpenIdConnectConstants.Properties.ConfidentialityLevel);
            if (!string.IsNullOrEmpty(confidentiality)) {
                identity.AddClaim(OpenIdConnectConstants.Claims.ConfidentialityLevel, confidentiality);
            }

            // Create a new claim per scope item, that will result
            // in a "scope" array being added in the access token.
            foreach (var scope in notification.Scopes) {
                identity.AddClaim(OpenIdConnectConstants.Claims.Scope, scope);
            }

            // Note: when used as an access token, a JWT token doesn't have to expose a "sub" claim
            // but the name identifier claim is used as a substitute when it has been explicitly added.
            // See https://tools.ietf.org/html/rfc7519#section-4.1.2
            var subject = identity.GetClaim(OpenIdConnectConstants.Claims.Subject);
            if (string.IsNullOrEmpty(subject)) {
                subject = identity.GetClaim(ClaimTypes.NameIdentifier) ??
                          identity.GetClaim(ClaimTypes.Upn);

                if (!string.IsNullOrEmpty(subject)) {
                    identity.AddClaim(OpenIdConnectConstants.Claims.Subject, subject);
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
            foreach (var audience in notification.Audiences) {
                identity.AddClaim(OpenIdConnectConstants.Claims.Audience, audience);
            }

            // Extract the presenters from the authentication ticket.
            var presenters = notification.Presenters.ToArray();
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

            var token = notification.SecurityTokenHandler.CreateToken(new SecurityTokenDescriptor {
                Subject = identity,
                Issuer = notification.Issuer,
                SigningCredentials = notification.SigningCredentials,
                IssuedAt = notification.Ticket.Properties.IssuedUtc?.UtcDateTime,
                NotBefore = notification.Ticket.Properties.IssuedUtc?.UtcDateTime,
                Expires = notification.Ticket.Properties.ExpiresUtc?.UtcDateTime
            });

            return notification.SecurityTokenHandler.WriteToken(token);
        }

        private async Task<string> SerializeIdentityTokenAsync(
            ClaimsPrincipal principal, AuthenticationProperties properties,
            OpenIdConnectRequest request, OpenIdConnectResponse response) {
            // Replace the principal by a new one containing only the filtered claims.
            // Actors identities are also filtered (delegation scenarios).
            principal = principal.Clone(claim => {
                // Never exclude the subject claims.
                if (string.Equals(claim.Type, OpenIdConnectConstants.Claims.Subject, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(claim.Type, ClaimTypes.NameIdentifier, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(claim.Type, ClaimTypes.Upn, StringComparison.OrdinalIgnoreCase)) {
                    return true;
                }

                // Claims whose destination is not explicitly referenced or doesn't
                // contain "id_token" are not included in the identity token.
                if (!claim.HasDestination(OpenIdConnectConstants.Destinations.IdentityToken)) {
                    Logger.LogDebug("'{Claim}' was excluded from the identity token claims.", claim.Type);

                    return false;
                }

                return true;
            });

            var identity = (ClaimsIdentity) principal.Identity;

            // Create a new ticket containing the updated properties and the filtered principal.
            var ticket = new AuthenticationTicket(principal, properties, Options.AuthenticationScheme);
            ticket.Properties.IssuedUtc = Options.SystemClock.UtcNow;
            ticket.Properties.ExpiresUtc = ticket.Properties.IssuedUtc +
                (ticket.GetIdentityTokenLifetime() ?? Options.IdentityTokenLifetime);

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
                SigningCredentials = Options.SigningCredentials.FirstOrDefault(key => key.Key is AsymmetricSecurityKey)
            };

            await Options.Provider.SerializeIdentityToken(notification);

            if (notification.HandledResponse || !string.IsNullOrEmpty(notification.IdentityToken)) {
                return notification.IdentityToken;
            }

            else if (notification.Skipped) {
                return null;
            }

            if (!ReferenceEquals(ticket, notification.Ticket)) {
                throw new InvalidOperationException("The authentication ticket cannot be replaced.");
            }

            if (notification.SecurityTokenHandler == null) {
                return null;
            }

            // Extract the main identity from the principal.
            identity = (ClaimsIdentity) ticket.Principal.Identity;

            if (string.IsNullOrEmpty(identity.GetClaim(OpenIdConnectConstants.Claims.Subject)) &&
                string.IsNullOrEmpty(identity.GetClaim(ClaimTypes.NameIdentifier)) &&
                string.IsNullOrEmpty(identity.GetClaim(ClaimTypes.Upn))) {
                throw new InvalidOperationException("The authentication ticket was rejected because " +
                                                    "it doesn't contain the mandatory subject claim.");
            }

            // Note: identity tokens must be signed but an exception is made by the OpenID Connect specification
            // when they are returned from the token endpoint: in this case, signing is not mandatory, as the TLS
            // server validation can be used as a way to ensure an identity token was issued by a trusted party.
            // See http://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation for more information.
            if (notification.SigningCredentials == null && request.IsAuthorizationRequest()) {
                throw new InvalidOperationException("A signing key must be provided.");
            }

            // Note: if the "sub" claim was not explicitly added, try to use
            // one of the other well-known name identifier/upn claims.
            var subject = identity.GetClaim(OpenIdConnectConstants.Claims.Subject);
            if (string.IsNullOrEmpty(subject)) {
                subject = identity.GetClaim(ClaimTypes.NameIdentifier) ??
                          identity.GetClaim(ClaimTypes.Upn);

                if (!string.IsNullOrEmpty(subject)) {
                    identity.AddClaim(OpenIdConnectConstants.Claims.Subject, subject);
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

            // Store the "unique_id" property as a claim.
            identity.AddClaim(OpenIdConnectConstants.Claims.JwtId, ticket.GetTicketId());

            // Store the "usage" property as a claim.
            identity.AddClaim(OpenIdConnectConstants.Claims.Usage, ticket.GetUsage());

            // Store the "confidentiality_level" property as a claim.
            var confidentiality = ticket.GetProperty(OpenIdConnectConstants.Properties.ConfidentialityLevel);
            if (!string.IsNullOrEmpty(confidentiality)) {
                identity.AddClaim(OpenIdConnectConstants.Claims.ConfidentialityLevel, confidentiality);
            }

            // Store the audiences as claims.
            foreach (var audience in notification.Audiences) {
                identity.AddClaim(OpenIdConnectConstants.Claims.Audience, audience);
            }

            // If a nonce was present in the authorization request, it MUST
            // be included in the id_token generated by the token endpoint.
            // See http://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
            var nonce = request.Nonce;
            if (request.IsAuthorizationCodeGrantType()) {
                // Restore the nonce stored in the authentication
                // ticket extracted from the authorization code.
                nonce = ticket.GetProperty(OpenIdConnectConstants.Properties.Nonce);
            }

            if (!string.IsNullOrEmpty(nonce)) {
                identity.AddClaim(OpenIdConnectConstants.Claims.Nonce, nonce);
            }

            if (notification.SigningCredentials != null && (!string.IsNullOrEmpty(response.Code) ||
                                                            !string.IsNullOrEmpty(response.AccessToken))) {
                using (var algorithm = OpenIdConnectServerHelpers.GetHashAlgorithm(notification.SigningCredentials.Algorithm)) {
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
            }

            // Extract the presenters from the authentication ticket.
            var presenters = notification.Presenters.ToArray();
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

            var token = notification.SecurityTokenHandler.CreateToken(new SecurityTokenDescriptor {
                Subject = identity,
                Issuer = notification.Issuer,
                SigningCredentials = notification.SigningCredentials,
                IssuedAt = notification.Ticket.Properties.IssuedUtc?.UtcDateTime,
                NotBefore = notification.Ticket.Properties.IssuedUtc?.UtcDateTime,
                Expires = notification.Ticket.Properties.ExpiresUtc?.UtcDateTime
            });

            return notification.SecurityTokenHandler.WriteToken(token);
        }

        private async Task<string> SerializeRefreshTokenAsync(
            ClaimsPrincipal principal, AuthenticationProperties properties,
            OpenIdConnectRequest request, OpenIdConnectResponse response) {
            // Note: claims in refresh tokens are never filtered as they are supposed to be opaque:
            // SerializeAccessTokenAsync and SerializeIdentityTokenAsync are responsible of ensuring
            // that subsequent access and identity tokens are correctly filtered.

            // Create a new ticket containing the updated properties.
            var ticket = new AuthenticationTicket(principal, properties, Options.AuthenticationScheme);
            ticket.Properties.IssuedUtc = Options.SystemClock.UtcNow;
            ticket.Properties.ExpiresUtc = ticket.Properties.IssuedUtc +
                (ticket.GetRefreshTokenLifetime() ?? Options.RefreshTokenLifetime);

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

            if (!ReferenceEquals(ticket, notification.Ticket)) {
                throw new InvalidOperationException("The authentication ticket cannot be replaced.");
            }

            return notification.DataFormat?.Protect(ticket);
        }

        private async Task<AuthenticationTicket> DeserializeAuthorizationCodeAsync(string code, OpenIdConnectRequest request) {
            var notification = new DeserializeAuthorizationCodeContext(Context, Options, request, code) {
                DataFormat = Options.AuthorizationCodeFormat
            };

            await Options.Provider.DeserializeAuthorizationCode(notification);

            if (notification.HandledResponse || notification.Ticket != null) {
                notification.Ticket.SetUsage(OpenIdConnectConstants.Usages.AuthorizationCode);

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
                Logger.LogDebug("The received token was not an authorization code: {Code}.", code);

                return null;
            }

            return ticket;
        }

        private async Task<AuthenticationTicket> DeserializeAccessTokenAsync(string token, OpenIdConnectRequest request) {
            var notification = new DeserializeAccessTokenContext(Context, Options, request, token) {
                DataFormat = Options.AccessTokenFormat,
                SecurityTokenHandler = Options.AccessTokenHandler
            };

            // Note: ValidateAudience and ValidateLifetime are always set to false:
            // if necessary, the audience and the expiration can be validated
            // in InvokeIntrospectionEndpointAsync or InvokeTokenEndpointAsync.
            notification.TokenValidationParameters = new TokenValidationParameters {
                IssuerSigningKeys = Options.SigningCredentials.Select(credentials => credentials.Key),
                ValidIssuer = Context.GetIssuer(Options),
                ValidateAudience = false,
                ValidateLifetime = false
            };

            await Options.Provider.DeserializeAccessToken(notification);

            if (notification.HandledResponse || notification.Ticket != null) {
                notification.Ticket.SetUsage(OpenIdConnectConstants.Usages.AccessToken);

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
                    Logger.LogDebug("The access token handler refused to read the token: {Token}", token);

                    return null;
                }

                principal = handler.ValidateToken(token, notification.TokenValidationParameters, out securityToken);
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

            var identifier = principal.FindFirst(OpenIdConnectConstants.Claims.JwtId);
            if (identifier != null) {
                ticket.SetTicketId(identifier.Value);
            }

            var usage = principal.FindFirst(OpenIdConnectConstants.Claims.Usage);
            if (usage != null) {
                ticket.SetUsage(usage.Value);
            }

            var confidentiality = principal.FindFirst(OpenIdConnectConstants.Claims.ConfidentialityLevel);
            if (confidentiality != null) {
                ticket.SetProperty(OpenIdConnectConstants.Properties.ConfidentialityLevel, confidentiality.Value);
            }

            // Ensure that e received ticket is an access token.
            if (!ticket.IsAccessToken()) {
                Logger.LogDebug("The received token was not an access token: {Token}.", token);

                return null;
            }

            return ticket;
        }

        private async Task<AuthenticationTicket> DeserializeIdentityTokenAsync(string token, OpenIdConnectRequest request) {
            var notification = new DeserializeIdentityTokenContext(Context, Options, request, token) {
                SecurityTokenHandler = Options.IdentityTokenHandler
            };

            // Note: ValidateAudience and ValidateLifetime are always set to false:
            // if necessary, the audience and the expiration can be validated
            // in InvokeIntrospectionEndpointAsync or InvokeTokenEndpointAsync.
            notification.TokenValidationParameters = new TokenValidationParameters {
                IssuerSigningKeys = Options.SigningCredentials.Select(credentials => credentials.Key),
                ValidIssuer = Context.GetIssuer(Options),
                ValidateAudience = false,
                ValidateLifetime = false
            };

            await Options.Provider.DeserializeIdentityToken(notification);

            if (notification.HandledResponse || notification.Ticket != null) {
                notification.Ticket.SetUsage(OpenIdConnectConstants.Usages.IdentityToken);

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
                    Logger.LogDebug("The identity token handler refused to read the token: {Token}", token);

                    return null;
                }

                principal = notification.SecurityTokenHandler.ValidateToken(token, notification.TokenValidationParameters, out securityToken);
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

            var confidentiality = principal.FindFirst(OpenIdConnectConstants.Claims.ConfidentialityLevel);
            if (confidentiality != null) {
                ticket.SetProperty(OpenIdConnectConstants.Properties.ConfidentialityLevel, confidentiality.Value);
            }

            // Ensure the received ticket is an identity token.
            if (!ticket.IsIdentityToken()) {
                Logger.LogDebug("The received token was not an identity token: {Token}.", token);

                return null;
            }

            return ticket;
        }

        private async Task<AuthenticationTicket> DeserializeRefreshTokenAsync(string token, OpenIdConnectRequest request) {
            var notification = new DeserializeRefreshTokenContext(Context, Options, request, token) {
                DataFormat = Options.RefreshTokenFormat
            };

            await Options.Provider.DeserializeRefreshToken(notification);

            if (notification.HandledResponse || notification.Ticket != null) {
                notification.Ticket.SetUsage(OpenIdConnectConstants.Usages.RefreshToken);

                return notification.Ticket;
            }

            else if (notification.Skipped) {
                return null;
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
