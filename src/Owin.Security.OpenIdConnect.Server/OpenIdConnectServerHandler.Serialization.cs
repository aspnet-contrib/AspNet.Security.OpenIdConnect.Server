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
using AspNet.Security.OpenIdConnect.Primitives;
using Microsoft.Extensions.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using Owin.Security.OpenIdConnect.Extensions;

namespace Owin.Security.OpenIdConnect.Server
{
    public partial class OpenIdConnectServerHandler : AuthenticationHandler<OpenIdConnectServerOptions>
    {
        private async Task<string> SerializeAuthorizationCodeAsync(
            ClaimsIdentity identity, AuthenticationProperties properties,
            OpenIdConnectRequest request, OpenIdConnectResponse response)
        {
            // Note: claims in authorization codes are never filtered as they are supposed to be opaque:
            // SerializeAccessTokenAsync and SerializeIdentityTokenAsync are responsible of ensuring
            // that subsequent access and identity tokens are correctly filtered.

            // Create a new ticket containing the updated properties.
            var ticket = new AuthenticationTicket(identity, properties);
            ticket.Properties.IssuedUtc = Options.SystemClock.UtcNow;
            ticket.Properties.ExpiresUtc = ticket.Properties.IssuedUtc;
            ticket.Properties.ExpiresUtc += ticket.GetAuthorizationCodeLifetime() ?? Options.AuthorizationCodeLifetime;

            ticket.SetUsage(OpenIdConnectConstants.Usages.AuthorizationCode);

            // Associate a random identifier with the authorization code.
            ticket.SetTicketId(Guid.NewGuid().ToString());

            // Store the code_challenge, code_challenge_method and nonce parameters for later comparison.
            ticket.SetProperty(OpenIdConnectConstants.Properties.CodeChallenge, request.CodeChallenge)
                  .SetProperty(OpenIdConnectConstants.Properties.CodeChallengeMethod, request.CodeChallengeMethod)
                  .SetProperty(OpenIdConnectConstants.Properties.Nonce, request.Nonce);

            // Store the original redirect_uri sent by the client application for later comparison.
            ticket.SetProperty(OpenIdConnectConstants.Properties.OriginalRedirectUri,
                request.GetProperty<string>(OpenIdConnectConstants.Properties.OriginalRedirectUri));

            // Remove the unwanted properties from the authentication ticket.
            ticket.RemoveProperty(OpenIdConnectConstants.Properties.AuthorizationCodeLifetime);

            var notification = new SerializeAuthorizationCodeContext(Context, Options, request, response, ticket)
            {
                DataFormat = Options.AuthorizationCodeFormat
            };

            await Options.Provider.SerializeAuthorizationCode(notification);

            if (notification.HandledResponse || !string.IsNullOrEmpty(notification.AuthorizationCode))
            {
                return notification.AuthorizationCode;
            }

            else if (notification.Skipped)
            {
                return null;
            }

            if (notification.DataFormat == null)
            {
                throw new InvalidOperationException("A data formatter must be provided.");
            }

            var result = notification.DataFormat.Protect(ticket);

            Logger.LogTrace("A new authorization code was successfully generated using " +
                            "the specified data format: {Code} ; {Claims} ; {Properties}.",
                            result, ticket.Identity.Claims, ticket.Properties.Dictionary);

            return result;
        }

        private async Task<string> SerializeAccessTokenAsync(
            ClaimsIdentity identity, AuthenticationProperties properties,
            OpenIdConnectRequest request, OpenIdConnectResponse response)
        {
            // Create a new identity containing only the filtered claims.
            // Actors identities are also filtered (delegation scenarios).
            identity = identity.Clone(claim =>
            {
                // Never exclude the subject claim.
                if (string.Equals(claim.Type, OpenIdConnectConstants.Claims.Subject, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }

                // Claims whose destination is not explicitly referenced or doesn't
                // contain "access_token" are not included in the access token.
                if (!claim.HasDestination(OpenIdConnectConstants.Destinations.AccessToken))
                {
                    Logger.LogDebug("'{Claim}' was excluded from the access token claims.", claim.Type);

                    return false;
                }

                return true;
            });

            // Remove the destinations from the claim properties.
            foreach (var claim in identity.Claims)
            {
                claim.Properties.Remove(OpenIdConnectConstants.Properties.Destinations);
            }

            // Create a new ticket containing the updated properties and the filtered identity.
            var ticket = new AuthenticationTicket(identity, properties);
            ticket.Properties.IssuedUtc = Options.SystemClock.UtcNow;
            ticket.Properties.ExpiresUtc = ticket.Properties.IssuedUtc;
            ticket.Properties.ExpiresUtc += ticket.GetAccessTokenLifetime() ?? Options.AccessTokenLifetime;

            ticket.SetUsage(OpenIdConnectConstants.Usages.AccessToken);
            ticket.SetAudiences(ticket.GetResources());

            // Associate a random identifier with the access token.
            ticket.SetTicketId(Guid.NewGuid().ToString());

            // Remove the unwanted properties from the authentication ticket.
            ticket.RemoveProperty(OpenIdConnectConstants.Properties.AccessTokenLifetime)
                  .RemoveProperty(OpenIdConnectConstants.Properties.AuthorizationCodeLifetime)
                  .RemoveProperty(OpenIdConnectConstants.Properties.CodeChallenge)
                  .RemoveProperty(OpenIdConnectConstants.Properties.CodeChallengeMethod)
                  .RemoveProperty(OpenIdConnectConstants.Properties.IdentityTokenLifetime)
                  .RemoveProperty(OpenIdConnectConstants.Properties.Nonce)
                  .RemoveProperty(OpenIdConnectConstants.Properties.OriginalRedirectUri)
                  .RemoveProperty(OpenIdConnectConstants.Properties.RefreshTokenLifetime);

            var notification = new SerializeAccessTokenContext(Context, Options, request, response, ticket)
            {
                DataFormat = Options.AccessTokenFormat,
                Issuer = Context.GetIssuer(Options),
                SecurityTokenHandler = Options.AccessTokenHandler,
                SigningCredentials = Options.SigningCredentials.FirstOrDefault(key => key.SigningKey is SymmetricSecurityKey) ??
                                     Options.SigningCredentials.FirstOrDefault()
            };

            await Options.Provider.SerializeAccessToken(notification);

            if (notification.HandledResponse || !string.IsNullOrEmpty(notification.AccessToken))
            {
                return notification.AccessToken;
            }

            else if (notification.Skipped)
            {
                return null;
            }

            if (notification.SecurityTokenHandler == null)
            {
                if (notification.DataFormat == null)
                {
                    throw new InvalidOperationException("A security token handler or data formatter must be provided.");
                }

                var value = notification.DataFormat.Protect(ticket);

                Logger.LogTrace("A new access token was successfully generated using the " +
                                "specified data format: {Token} ; {Claims} ; {Properties}.",
                                value, ticket.Identity.Claims, ticket.Properties.Dictionary);

                return value;
            }

            // At this stage, throw an exception if no signing credentials were provided.
            if (notification.SigningCredentials == null)
            {
                throw new InvalidOperationException("A signing key must be provided.");
            }

            // Store the "unique_id" property as a claim.
            ticket.Identity.AddClaim(OpenIdConnectConstants.Claims.JwtId, ticket.GetTicketId());

            // Store the "usage" property as a claim.
            ticket.Identity.AddClaim(OpenIdConnectConstants.Claims.Usage, ticket.GetUsage());

            // Store the "confidentiality_level" property as a claim.
            var confidentiality = ticket.GetProperty(OpenIdConnectConstants.Properties.ConfidentialityLevel);
            if (!string.IsNullOrEmpty(confidentiality))
            {
                identity.AddClaim(OpenIdConnectConstants.Claims.ConfidentialityLevel, confidentiality);
            }

            // Create a new claim per scope item, that will result
            // in a "scope" array being added in the access token.
            foreach (var scope in notification.Scopes)
            {
                ticket.Identity.AddClaim(OpenIdConnectConstants.Claims.Scope, scope);
            }

            // Store the audiences as claims.
            foreach (var audience in notification.Audiences)
            {
                ticket.Identity.AddClaim(OpenIdConnectConstants.Claims.Audience, audience);
            }

            // Extract the presenters from the authentication ticket.
            var presenters = notification.Presenters.ToArray();
            switch (presenters.Length)
            {
                case 0: break;

                case 1:
                    ticket.Identity.AddClaim(OpenIdConnectConstants.Claims.AuthorizedParty, presenters[0]);
                    break;

                default:
                    Logger.LogWarning("Multiple presenters have been associated with the access token " +
                                      "but the JWT format only accepts single values.");

                    // Only add the first authorized party.
                    ticket.Identity.AddClaim(OpenIdConnectConstants.Claims.AuthorizedParty, presenters[0]);
                    break;
            }

            if (ticket.Properties.IssuedUtc != null)
            {
                ticket.Identity.AddClaim(new Claim(
                    OpenIdConnectConstants.Claims.IssuedAt,
                    EpochTime.GetIntDate(ticket.Properties.IssuedUtc.Value.UtcDateTime).ToString(),
                    ClaimValueTypes.Integer64));
            }

            var token = notification.SecurityTokenHandler.CreateToken(new SecurityTokenDescriptor
            {
                Subject = ticket.Identity,
                TokenIssuerName = notification.Issuer,
                SigningCredentials = notification.SigningCredentials,
                Lifetime = new Lifetime(
                    notification.Ticket.Properties.IssuedUtc?.UtcDateTime,
                    notification.Ticket.Properties.ExpiresUtc?.UtcDateTime)
            });

            var result = notification.SecurityTokenHandler.WriteToken(token);

            Logger.LogTrace("A new access token was successfully generated using the specified " +
                            "security token handler: {Token} ; {Claims} ; {Properties}.",
                            result, ticket.Identity.Claims, ticket.Properties.Dictionary);

            return result;
        }

        private async Task<string> SerializeIdentityTokenAsync(
            ClaimsIdentity identity, AuthenticationProperties properties,
            OpenIdConnectRequest request, OpenIdConnectResponse response)
        {
            // Replace the identity by a new one containing only the filtered claims.
            // Actors identities are also filtered (delegation scenarios).
            identity = identity.Clone(claim =>
            {
                // Never exclude the subject claim.
                if (string.Equals(claim.Type, OpenIdConnectConstants.Claims.Subject, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }

                // Claims whose destination is not explicitly referenced or doesn't
                // contain "id_token" are not included in the identity token.
                if (!claim.HasDestination(OpenIdConnectConstants.Destinations.IdentityToken))
                {
                    Logger.LogDebug("'{Claim}' was excluded from the identity token claims.", claim.Type);

                    return false;
                }

                return true;
            });

            // Remove the destinations from the claim properties.
            foreach (var claim in identity.Claims)
            {
                claim.Properties.Remove(OpenIdConnectConstants.Properties.Destinations);
            }

            // Create a new ticket containing the updated properties and the filtered identity.
            var ticket = new AuthenticationTicket(identity, properties);
            ticket.Properties.IssuedUtc = Options.SystemClock.UtcNow;
            ticket.Properties.ExpiresUtc = ticket.Properties.IssuedUtc;
            ticket.Properties.ExpiresUtc += ticket.GetIdentityTokenLifetime() ?? Options.IdentityTokenLifetime;

            ticket.SetUsage(OpenIdConnectConstants.Usages.IdentityToken);

            // Associate a random identifier with the identity token.
            ticket.SetTicketId(Guid.NewGuid().ToString());

            // Remove the unwanted properties from the authentication ticket.
            ticket.RemoveProperty(OpenIdConnectConstants.Properties.AccessTokenLifetime)
                  .RemoveProperty(OpenIdConnectConstants.Properties.AuthorizationCodeLifetime)
                  .RemoveProperty(OpenIdConnectConstants.Properties.CodeChallenge)
                  .RemoveProperty(OpenIdConnectConstants.Properties.CodeChallengeMethod)
                  .RemoveProperty(OpenIdConnectConstants.Properties.IdentityTokenLifetime)
                  .RemoveProperty(OpenIdConnectConstants.Properties.OriginalRedirectUri)
                  .RemoveProperty(OpenIdConnectConstants.Properties.RefreshTokenLifetime);

            ticket.SetAudiences(ticket.GetPresenters());

            var notification = new SerializeIdentityTokenContext(Context, Options, request, response, ticket)
            {
                Issuer = Context.GetIssuer(Options),
                SecurityTokenHandler = Options.IdentityTokenHandler,
                SigningCredentials = Options.SigningCredentials.FirstOrDefault(key => key.SigningKey is AsymmetricSecurityKey)
            };

            await Options.Provider.SerializeIdentityToken(notification);

            if (notification.HandledResponse || !string.IsNullOrEmpty(notification.IdentityToken))
            {
                return notification.IdentityToken;
            }

            else if (notification.Skipped)
            {
                return null;
            }

            if (notification.SecurityTokenHandler == null)
            {
                throw new InvalidOperationException("A security token handler must be provided.");
            }

            if (string.IsNullOrEmpty(identity.GetClaim(OpenIdConnectConstants.Claims.Subject)))
            {
                throw new InvalidOperationException("The authentication ticket was rejected because " +
                                                    "the mandatory subject claim was missing.");
            }

            // Note: identity tokens must be signed but an exception is made by the OpenID Connect specification
            // when they are returned from the token endpoint: in this case, signing is not mandatory, as the TLS
            // server validation can be used as a way to ensure an identity token was issued by a trusted party.
            // See http://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation for more information.
            if (notification.SigningCredentials == null && request.IsAuthorizationRequest())
            {
                throw new InvalidOperationException("A signing key must be provided.");
            }

            // Store the "unique_id" property as a claim.
            ticket.Identity.AddClaim(OpenIdConnectConstants.Claims.JwtId, ticket.GetTicketId());

            // Store the "usage" property as a claim.
            ticket.Identity.AddClaim(OpenIdConnectConstants.Claims.Usage, ticket.GetUsage());

            // Store the "confidentiality_level" property as a claim.
            var confidentiality = ticket.GetProperty(OpenIdConnectConstants.Properties.ConfidentialityLevel);
            if (!string.IsNullOrEmpty(confidentiality))
            {
                identity.AddClaim(OpenIdConnectConstants.Claims.ConfidentialityLevel, confidentiality);
            }

            // Store the audiences as claims.
            foreach (var audience in notification.Audiences)
            {
                ticket.Identity.AddClaim(OpenIdConnectConstants.Claims.Audience, audience);
            }

            // If a nonce was present in the authorization request, it MUST
            // be included in the id_token generated by the token endpoint.
            // See http://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
            var nonce = request.Nonce;
            if (request.IsAuthorizationCodeGrantType())
            {
                // Restore the nonce stored in the authentication
                // ticket extracted from the authorization code.
                nonce = ticket.GetProperty(OpenIdConnectConstants.Properties.Nonce);
            }

            if (!string.IsNullOrEmpty(nonce))
            {
                ticket.Identity.AddClaim(OpenIdConnectConstants.Claims.Nonce, nonce);
            }

            if (notification.SigningCredentials != null && (!string.IsNullOrEmpty(response.Code) ||
                                                            !string.IsNullOrEmpty(response.AccessToken)))
            {
                using (var algorithm = HashAlgorithm.Create(notification.SigningCredentials.DigestAlgorithm))
                {
                    // Create an authorization code hash if necessary.
                    if (!string.IsNullOrEmpty(response.Code))
                    {
                        var hash = algorithm.ComputeHash(Encoding.ASCII.GetBytes(response.Code));

                        // Note: only the left-most half of the hash of the octets is used.
                        // See http://openid.net/specs/openid-connect-core-1_0.html#HybridIDToken
                        identity.AddClaim(OpenIdConnectConstants.Claims.CodeHash, Base64UrlEncoder.Encode(hash, 0, hash.Length / 2));
                    }

                    // Create an access token hash if necessary.
                    if (!string.IsNullOrEmpty(response.AccessToken))
                    {
                        var hash = algorithm.ComputeHash(Encoding.ASCII.GetBytes(response.AccessToken));

                        // Note: only the left-most half of the hash of the octets is used.
                        // See http://openid.net/specs/openid-connect-core-1_0.html#CodeIDToken
                        identity.AddClaim(OpenIdConnectConstants.Claims.AccessTokenHash, Base64UrlEncoder.Encode(hash, 0, hash.Length / 2));
                    }
                }
            }

            // Extract the presenters from the authentication ticket.
            var presenters = notification.Presenters.ToArray();
            switch (presenters.Length)
            {
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

            if (ticket.Properties.IssuedUtc != null)
            {
                ticket.Identity.AddClaim(new Claim(
                    OpenIdConnectConstants.Claims.IssuedAt,
                    EpochTime.GetIntDate(ticket.Properties.IssuedUtc.Value.UtcDateTime).ToString(),
                    ClaimValueTypes.Integer64));
            }

            var token = notification.SecurityTokenHandler.CreateToken(new SecurityTokenDescriptor
            {
                Subject = ticket.Identity,
                TokenIssuerName = notification.Issuer,
                SigningCredentials = notification.SigningCredentials,
                Lifetime = new Lifetime(
                    notification.Ticket.Properties.IssuedUtc?.UtcDateTime,
                    notification.Ticket.Properties.ExpiresUtc?.UtcDateTime)
            });

            var result = notification.SecurityTokenHandler.WriteToken(token);

            Logger.LogTrace("A new identity token was successfully generated using the specified " +
                            "security token handler: {Token} ; {Claims} ; {Properties}.",
                            result, ticket.Identity.Claims, ticket.Properties.Dictionary);

            return result;
        }

        private async Task<string> SerializeRefreshTokenAsync(
            ClaimsIdentity identity, AuthenticationProperties properties,
            OpenIdConnectRequest request, OpenIdConnectResponse response)
        {
            // Note: claims in refresh tokens are never filtered as they are supposed to be opaque:
            // SerializeAccessTokenAsync and SerializeIdentityTokenAsync are responsible of ensuring
            // that subsequent access and identity tokens are correctly filtered.

            // Create a new ticket containing the updated properties.
            var ticket = new AuthenticationTicket(identity, properties);
            ticket.Properties.IssuedUtc = Options.SystemClock.UtcNow;
            ticket.Properties.ExpiresUtc = ticket.Properties.IssuedUtc;
            ticket.Properties.ExpiresUtc += ticket.GetRefreshTokenLifetime() ?? Options.RefreshTokenLifetime;

            ticket.SetUsage(OpenIdConnectConstants.Usages.RefreshToken);

            // Associate a random identifier with the refresh token.
            ticket.SetTicketId(Guid.NewGuid().ToString());

            // Remove the unwanted properties from the authentication ticket.
            ticket.RemoveProperty(OpenIdConnectConstants.Properties.AuthorizationCodeLifetime)
                  .RemoveProperty(OpenIdConnectConstants.Properties.CodeChallenge)
                  .RemoveProperty(OpenIdConnectConstants.Properties.CodeChallengeMethod)
                  .RemoveProperty(OpenIdConnectConstants.Properties.Nonce)
                  .RemoveProperty(OpenIdConnectConstants.Properties.OriginalRedirectUri);

            var notification = new SerializeRefreshTokenContext(Context, Options, request, response, ticket)
            {
                DataFormat = Options.RefreshTokenFormat
            };

            await Options.Provider.SerializeRefreshToken(notification);

            if (notification.HandledResponse || !string.IsNullOrEmpty(notification.RefreshToken))
            {
                return notification.RefreshToken;
            }

            else if (notification.Skipped)
            {
                return null;
            }

            if (notification.DataFormat == null)
            {
                throw new InvalidOperationException("A data formatter must be provided.");
            }

            var result = notification.DataFormat.Protect(ticket);

            Logger.LogTrace("A new refresh token was successfully generated using the " +
                            "specified data format: {Token} ; {Claims} ; {Properties}.",
                            result, ticket.Identity.Claims, ticket.Properties.Dictionary);

            return result;
        }

        private async Task<AuthenticationTicket> DeserializeAuthorizationCodeAsync(string code, OpenIdConnectRequest request)
        {
            var notification = new DeserializeAuthorizationCodeContext(Context, Options, request, code)
            {
                DataFormat = Options.AuthorizationCodeFormat
            };

            await Options.Provider.DeserializeAuthorizationCode(notification);

            if (notification.HandledResponse || notification.Ticket != null)
            {
                notification.Ticket.SetUsage(OpenIdConnectConstants.Usages.AuthorizationCode);

                return notification.Ticket;
            }

            else if (notification.Skipped)
            {
                return null;
            }

            if (notification.DataFormat == null)
            {
                throw new InvalidOperationException("A data formatter must be provided.");
            }

            var ticket = notification.DataFormat.Unprotect(code);
            if (ticket == null)
            {
                Logger.LogTrace("The received token was invalid or malformed: {Code}.", code);

                return null;
            }

            // Ensure the received ticket is an authorization code.
            if (!ticket.IsAuthorizationCode())
            {
                Logger.LogTrace("The received token was not an authorization code: {Code}.", code);

                return null;
            }

            Logger.LogTrace("The authorization code '{Code}' was successfully validated using " +
                            "the specified token data format: {Claims} ; {Properties}.",
                            code, ticket.Identity.Claims, ticket.Properties.Dictionary);

            return ticket;
        }

        private async Task<AuthenticationTicket> DeserializeAccessTokenAsync(string token, OpenIdConnectRequest request)
        {
            var notification = new DeserializeAccessTokenContext(Context, Options, request, token)
            {
                DataFormat = Options.AccessTokenFormat,
                SecurityTokenHandler = Options.AccessTokenHandler
            };

            // Note: ValidateAudience and ValidateLifetime are always set to false:
            // if necessary, the audience and the expiration can be validated
            // in InvokeIntrospectionEndpointAsync or InvokeTokenEndpointAsync.
            notification.TokenValidationParameters = new TokenValidationParameters
            {
                IssuerSigningKeys = Options.SigningCredentials.Select(credentials => credentials.SigningKey),
                NameClaimType = OpenIdConnectConstants.Claims.Name,
                RoleClaimType = OpenIdConnectConstants.Claims.Role,
                ValidIssuer = Context.GetIssuer(Options),
                ValidateAudience = false,
                ValidateLifetime = false
            };

            await Options.Provider.DeserializeAccessToken(notification);

            if (notification.HandledResponse || notification.Ticket != null)
            {
                notification.Ticket.SetUsage(OpenIdConnectConstants.Usages.AccessToken);

                return notification.Ticket;
            }

            else if (notification.Skipped)
            {
                return null;
            }

            var handler = notification.SecurityTokenHandler as ISecurityTokenValidator;
            if (handler == null)
            {
                if (notification.DataFormat == null)
                {
                    throw new InvalidOperationException("A security token handler or data formatter must be provided.");
                }

                var value = notification.DataFormat.Unprotect(token);
                if (value == null)
                {
                    Logger.LogTrace("The received token was invalid or malformed: {Token}.", value);

                    return null;
                }

                Logger.LogTrace("The access token '{Token}' was successfully validated using " +
                                "the specified token data format: {Claims} ; {Properties}.",
                                token, value.Identity.Claims, value.Properties.Dictionary);

                return value;
            }

            SecurityToken securityToken;
            ClaimsPrincipal principal;

            try
            {
                if (!handler.CanReadToken(token))
                {
                    Logger.LogTrace("The access token '{Token}' was rejected by the security token handler.", token);

                    return null;
                }

                principal = handler.ValidateToken(token, notification.TokenValidationParameters, out securityToken);
            }

            catch (Exception exception)
            {
                Logger.LogDebug("An exception occured while deserializing an access token: {Exception}.", exception);

                return null;
            }

            // Parameters stored in AuthenticationProperties are lost
            // when the identity token is serialized using a security token handler.
            // To mitigate that, they are inferred from the claims or the security token.
            var properties = new AuthenticationProperties
            {
                ExpiresUtc = securityToken.ValidTo,
                IssuedUtc = securityToken.ValidFrom
            };

            var ticket = new AuthenticationTicket((ClaimsIdentity) principal.Identity, properties);

            var audiences = principal.FindAll(OpenIdConnectConstants.Claims.Audience);
            if (audiences.Any())
            {
                ticket.SetAudiences(audiences.Select(claim => claim.Value));
            }

            var presenters = principal.FindAll(OpenIdConnectConstants.Claims.AuthorizedParty);
            if (presenters.Any())
            {
                ticket.SetPresenters(presenters.Select(claim => claim.Value));
            }

            var scopes = principal.FindAll(OpenIdConnectConstants.Claims.Scope);
            if (scopes.Any())
            {
                ticket.SetScopes(scopes.Select(claim => claim.Value));
            }

            var identifier = principal.FindFirst(OpenIdConnectConstants.Claims.JwtId);
            if (identifier != null)
            {
                ticket.SetTicketId(identifier.Value);
            }

            var usage = principal.FindFirst(OpenIdConnectConstants.Claims.Usage);
            if (usage != null)
            {
                ticket.SetUsage(usage.Value);
            }

            var confidentiality = principal.FindFirst(OpenIdConnectConstants.Claims.ConfidentialityLevel);
            if (confidentiality != null)
            {
                ticket.SetProperty(OpenIdConnectConstants.Properties.ConfidentialityLevel, confidentiality.Value);
            }

            // Ensure the received ticket is an access token.
            if (!ticket.IsAccessToken())
            {
                Logger.LogTrace("The received token was not an access token: {Token}.", token);

                return null;
            }

            Logger.LogTrace("The access token '{Token}' was successfully validated using " +
                            "the specified security token handler: {Claims} ; {Properties}.",
                            token, ticket.Identity.Claims, ticket.Properties.Dictionary);

            return ticket;
        }

        private async Task<AuthenticationTicket> DeserializeIdentityTokenAsync(string token, OpenIdConnectRequest request)
        {
            var notification = new DeserializeIdentityTokenContext(Context, Options, request, token)
            {
                SecurityTokenHandler = Options.IdentityTokenHandler
            };

            // Note: ValidateAudience and ValidateLifetime are always set to false:
            // if necessary, the audience and the expiration can be validated
            // in InvokeIntrospectionEndpointAsync or InvokeTokenEndpointAsync.
            notification.TokenValidationParameters = new TokenValidationParameters
            {
                IssuerSigningKeys = Options.SigningCredentials.Select(credentials => credentials.SigningKey)
                                                              .Where(key => key is AsymmetricSecurityKey),

                NameClaimType = OpenIdConnectConstants.Claims.Name,
                RoleClaimType = OpenIdConnectConstants.Claims.Role,
                ValidIssuer = Context.GetIssuer(Options),
                ValidateAudience = false,
                ValidateLifetime = false
            };

            await Options.Provider.DeserializeIdentityToken(notification);

            if (notification.HandledResponse || notification.Ticket != null)
            {
                notification.Ticket.SetUsage(OpenIdConnectConstants.Usages.IdentityToken);

                return notification.Ticket;
            }

            else if (notification.Skipped)
            {
                return null;
            }

            if (notification.SecurityTokenHandler == null)
            {
                throw new InvalidOperationException("A security token handler must be provided.");
            }

            SecurityToken securityToken;
            ClaimsPrincipal principal;

            try
            {
                if (!notification.SecurityTokenHandler.CanReadToken(token))
                {
                    Logger.LogTrace("The identity token '{Token}' was rejected by the security token handler.", token);

                    return null;
                }

                principal = notification.SecurityTokenHandler.ValidateToken(token, notification.TokenValidationParameters, out securityToken);
            }

            catch (Exception exception)
            {
                Logger.LogDebug("An exception occured while deserializing an identity token: {Exception}.", exception);

                return null;
            }

            // Parameters stored in AuthenticationProperties are lost
            // when the identity token is serialized using a security token handler.
            // To mitigate that, they are inferred from the claims or the security token.
            var properties = new AuthenticationProperties
            {
                ExpiresUtc = securityToken.ValidTo,
                IssuedUtc = securityToken.ValidFrom
            };

            var ticket = new AuthenticationTicket((ClaimsIdentity) principal.Identity, properties);

            var audiences = principal.FindAll(OpenIdConnectConstants.Claims.Audience);
            if (audiences.Any())
            {
                ticket.SetAudiences(audiences.Select(claim => claim.Value));
            }

            var presenters = principal.FindAll(OpenIdConnectConstants.Claims.AuthorizedParty);
            if (presenters.Any())
            {
                ticket.SetPresenters(presenters.Select(claim => claim.Value));
            }

            var identifier = principal.FindFirst(OpenIdConnectConstants.Claims.JwtId);
            if (identifier != null)
            {
                ticket.SetTicketId(identifier.Value);
            }

            var usage = principal.FindFirst(OpenIdConnectConstants.Claims.Usage);
            if (usage != null)
            {
                ticket.SetUsage(usage.Value);
            }

            var confidentiality = principal.FindFirst(OpenIdConnectConstants.Claims.ConfidentialityLevel);
            if (confidentiality != null)
            {
                ticket.SetProperty(OpenIdConnectConstants.Properties.ConfidentialityLevel, confidentiality.Value);
            }

            // Ensure the received ticket is an identity token.
            if (!ticket.IsIdentityToken())
            {
                Logger.LogTrace("The received token was not an identity token: {Token}.", token);

                return null;
            }

            Logger.LogTrace("The identity token '{Token}' was successfully validated using " +
                            "the specified security token handler: {Claims} ; {Properties}.",
                            token, ticket.Identity.Claims, ticket.Properties.Dictionary);

            return ticket;
        }

        private async Task<AuthenticationTicket> DeserializeRefreshTokenAsync(string token, OpenIdConnectRequest request)
        {
            var notification = new DeserializeRefreshTokenContext(Context, Options, request, token)
            {
                DataFormat = Options.RefreshTokenFormat
            };

            await Options.Provider.DeserializeRefreshToken(notification);

            if (notification.HandledResponse || notification.Ticket != null)
            {
                notification.Ticket.SetUsage(OpenIdConnectConstants.Usages.RefreshToken);

                return notification.Ticket;
            }

            else if (notification.Skipped)
            {
                return null;
            }

            if (notification.DataFormat == null)
            {
                throw new InvalidOperationException("A data formatter must be provided.");
            }

            var ticket = notification.DataFormat.Unprotect(token);
            if (ticket == null)
            {
                Logger.LogTrace("The received token was invalid or malformed: {Token}.", token);

                return null;
            }

            // Ensure the received ticket is an identity token.
            if (!ticket.IsRefreshToken())
            {
                Logger.LogTrace("The received token was not a refresh token: {Token}.", token);

                return null;
            }

            Logger.LogTrace("The refresh token '{Token}' was successfully validated using " +
                            "the specified token data format: {Claims} ; {Properties}.",
                            token, ticket.Identity.Claims, ticket.Properties.Dictionary);

            return ticket;
        }
    }
}
