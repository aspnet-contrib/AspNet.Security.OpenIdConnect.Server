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
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;

namespace AspNet.Security.OpenIdConnect.Server
{
    public partial class OpenIdConnectServerHandler
    {
        private async Task<string> SerializeAuthorizationCodeAsync(
            ClaimsPrincipal principal, AuthenticationProperties properties,
            OpenIdConnectRequest request, OpenIdConnectResponse response)
        {
            // Note: claims in authorization codes are never filtered as they are supposed to be opaque:
            // SerializeAccessTokenAsync and SerializeIdentityTokenAsync are responsible of ensuring
            // that subsequent access and identity tokens are correctly filtered.

            // Create a new ticket containing the updated properties.
            var ticket = new AuthenticationTicket(principal, properties, Scheme.Name);
            ticket.Properties.IssuedUtc = Options.SystemClock.UtcNow;

            // Only set the expiration date if a lifetime was specified in either the ticket or the options.
            var lifetime = ticket.GetAuthorizationCodeLifetime() ?? Options.AuthorizationCodeLifetime;
            if (lifetime.HasValue)
            {
                ticket.Properties.ExpiresUtc = ticket.Properties.IssuedUtc + lifetime.Value;
            }

            // Associate a random identifier with the authorization code.
            ticket.SetTokenId(Guid.NewGuid().ToString());

            // Store the code_challenge, code_challenge_method and nonce parameters for later comparison.
            ticket.SetProperty(OpenIdConnectConstants.Properties.CodeChallenge, request.CodeChallenge)
                  .SetProperty(OpenIdConnectConstants.Properties.CodeChallengeMethod, request.CodeChallengeMethod)
                  .SetProperty(OpenIdConnectConstants.Properties.Nonce, request.Nonce);

            // Store the original redirect_uri sent by the client application for later comparison.
            ticket.SetProperty(OpenIdConnectConstants.Properties.OriginalRedirectUri,
                request.GetProperty<string>(OpenIdConnectConstants.Properties.OriginalRedirectUri));

            // Remove the unwanted properties from the authentication ticket.
            ticket.RemoveProperty(OpenIdConnectConstants.Properties.AuthorizationCodeLifetime)
                  .RemoveProperty(OpenIdConnectConstants.Properties.TokenUsage);

            var notification = new SerializeAuthorizationCodeContext(Context, Scheme, Options, request, response, ticket)
            {
                DataFormat = Options.AuthorizationCodeFormat
            };

            await Provider.SerializeAuthorizationCode(notification);

            if (notification.IsHandled || !string.IsNullOrEmpty(notification.AuthorizationCode))
            {
                return notification.AuthorizationCode;
            }

            if (notification.DataFormat == null)
            {
                throw new InvalidOperationException("A data formatter must be provided.");
            }

            var result = notification.DataFormat.Protect(ticket);

            Logger.LogTrace("A new authorization code was successfully generated using " +
                            "the specified data format: {Code} ; {Claims} ; {Properties}.",
                            result, ticket.Principal.Claims, ticket.Properties.Items);

            return result;
        }

        private async Task<string> SerializeAccessTokenAsync(
            ClaimsPrincipal principal, AuthenticationProperties properties,
            OpenIdConnectRequest request, OpenIdConnectResponse response)
        {
            // Create a new principal containing only the filtered claims.
            // Actors identities are also filtered (delegation scenarios).
            principal = principal.Clone(claim =>
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
            foreach (var claim in principal.Claims)
            {
                claim.Properties.Remove(OpenIdConnectConstants.Properties.Destinations);
            }

            var identity = (ClaimsIdentity) principal.Identity;

            // Create a new ticket containing the updated properties and the filtered principal.
            var ticket = new AuthenticationTicket(principal, properties, Scheme.Name);
            ticket.Properties.IssuedUtc = Options.SystemClock.UtcNow;

            // Only set the expiration date if a lifetime was specified in either the ticket or the options.
            var lifetime = ticket.GetAccessTokenLifetime() ?? Options.AccessTokenLifetime;
            if (lifetime.HasValue)
            {
                ticket.Properties.ExpiresUtc = ticket.Properties.IssuedUtc + lifetime.Value;
            }

            // Associate a random identifier with the access token.
            ticket.SetTokenId(Guid.NewGuid().ToString());
            ticket.SetAudiences(ticket.GetResources());

            // Remove the unwanted properties from the authentication ticket.
            ticket.RemoveProperty(OpenIdConnectConstants.Properties.AccessTokenLifetime)
                  .RemoveProperty(OpenIdConnectConstants.Properties.AuthorizationCodeLifetime)
                  .RemoveProperty(OpenIdConnectConstants.Properties.CodeChallenge)
                  .RemoveProperty(OpenIdConnectConstants.Properties.CodeChallengeMethod)
                  .RemoveProperty(OpenIdConnectConstants.Properties.IdentityTokenLifetime)
                  .RemoveProperty(OpenIdConnectConstants.Properties.Nonce)
                  .RemoveProperty(OpenIdConnectConstants.Properties.OriginalRedirectUri)
                  .RemoveProperty(OpenIdConnectConstants.Properties.RefreshTokenLifetime)
                  .RemoveProperty(OpenIdConnectConstants.Properties.TokenUsage);

            var notification = new SerializeAccessTokenContext(Context, Scheme, Options, request, response, ticket)
            {
                DataFormat = Options.AccessTokenFormat,
                EncryptingCredentials = Options.EncryptingCredentials.FirstOrDefault(
                    credentials => credentials.Key is SymmetricSecurityKey),
                Issuer = Context.GetIssuer(Options),
                SecurityTokenHandler = Options.AccessTokenHandler,
                SigningCredentials = Options.SigningCredentials.FirstOrDefault(
                    credentials => credentials.Key is SymmetricSecurityKey) ?? Options.SigningCredentials.FirstOrDefault()
            };

            await Provider.SerializeAccessToken(notification);

            if (notification.IsHandled || !string.IsNullOrEmpty(notification.AccessToken))
            {
                return notification.AccessToken;
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
                                value, ticket.Principal.Claims, ticket.Properties.Items);

                return value;
            }

            // At this stage, throw an exception if no signing credentials were provided.
            if (notification.SigningCredentials == null)
            {
                throw new InvalidOperationException("A signing key must be provided.");
            }

            // Extract the main identity from the principal.
            identity = (ClaimsIdentity) ticket.Principal.Identity;

            // Store the "usage" property as a claim.
            identity.AddClaim(OpenIdConnectConstants.Claims.TokenUsage, OpenIdConnectConstants.TokenUsages.AccessToken);

            // Store the "unique_id" property as a claim.
            identity.AddClaim(OpenIdConnectConstants.Claims.JwtId, ticket.GetTokenId());

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
                identity.AddClaim(OpenIdConnectConstants.Claims.Scope, scope);
            }

            // Store the audiences as claims.
            foreach (var audience in notification.Audiences)
            {
                identity.AddClaim(OpenIdConnectConstants.Claims.Audience, audience);
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
                    Logger.LogWarning("Multiple presenters have been associated with the access token " +
                                      "but the JWT format only accepts single values.");

                    // Only add the first authorized party.
                    identity.AddClaim(OpenIdConnectConstants.Claims.AuthorizedParty, presenters[0]);
                    break;
            }

            var token = notification.SecurityTokenHandler.CreateEncodedJwt(new SecurityTokenDescriptor
            {
                Subject = identity,
                Issuer = notification.Issuer,
                EncryptingCredentials = notification.EncryptingCredentials,
                SigningCredentials = notification.SigningCredentials,
                IssuedAt = notification.Ticket.Properties.IssuedUtc?.UtcDateTime,
                NotBefore = notification.Ticket.Properties.IssuedUtc?.UtcDateTime,
                Expires = notification.Ticket.Properties.ExpiresUtc?.UtcDateTime
            });

            Logger.LogTrace("A new access token was successfully generated using the specified " +
                            "security token handler: {Token} ; {Claims} ; {Properties}.",
                            token, ticket.Principal.Claims, ticket.Properties.Items);

            return token;
        }

        private async Task<string> SerializeIdentityTokenAsync(
            ClaimsPrincipal principal, AuthenticationProperties properties,
            OpenIdConnectRequest request, OpenIdConnectResponse response)
        {
            // Replace the principal by a new one containing only the filtered claims.
            // Actors identities are also filtered (delegation scenarios).
            principal = principal.Clone(claim =>
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
            foreach (var claim in principal.Claims)
            {
                claim.Properties.Remove(OpenIdConnectConstants.Properties.Destinations);
            }

            var identity = (ClaimsIdentity) principal.Identity;

            // Create a new ticket containing the updated properties and the filtered principal.
            var ticket = new AuthenticationTicket(principal, properties, Scheme.Name);
            ticket.Properties.IssuedUtc = Options.SystemClock.UtcNow;

            // Only set the expiration date if a lifetime was specified in either the ticket or the options.
            var lifetime = ticket.GetIdentityTokenLifetime() ?? Options.IdentityTokenLifetime;
            if (lifetime.HasValue)
            {
                ticket.Properties.ExpiresUtc = ticket.Properties.IssuedUtc + lifetime.Value;
            }

            // Associate a random identifier with the identity token.
            ticket.SetTokenId(Guid.NewGuid().ToString());

            // Remove the unwanted properties from the authentication ticket.
            ticket.RemoveProperty(OpenIdConnectConstants.Properties.AccessTokenLifetime)
                  .RemoveProperty(OpenIdConnectConstants.Properties.AuthorizationCodeLifetime)
                  .RemoveProperty(OpenIdConnectConstants.Properties.CodeChallenge)
                  .RemoveProperty(OpenIdConnectConstants.Properties.CodeChallengeMethod)
                  .RemoveProperty(OpenIdConnectConstants.Properties.IdentityTokenLifetime)
                  .RemoveProperty(OpenIdConnectConstants.Properties.OriginalRedirectUri)
                  .RemoveProperty(OpenIdConnectConstants.Properties.RefreshTokenLifetime)
                  .RemoveProperty(OpenIdConnectConstants.Properties.TokenUsage);

            ticket.SetAudiences(ticket.GetPresenters());

            var notification = new SerializeIdentityTokenContext(Context, Scheme, Options, request, response, ticket)
            {
                Issuer = Context.GetIssuer(Options),
                SecurityTokenHandler = Options.IdentityTokenHandler,
                SigningCredentials = Options.SigningCredentials.FirstOrDefault(
                    credentials => credentials.Key is AsymmetricSecurityKey)
            };

            await Provider.SerializeIdentityToken(notification);

            if (notification.IsHandled || !string.IsNullOrEmpty(notification.IdentityToken))
            {
                return notification.IdentityToken;
            }

            if (notification.SecurityTokenHandler == null)
            {
                throw new InvalidOperationException("A security token handler must be provided.");
            }

            // Extract the main identity from the principal.
            identity = (ClaimsIdentity) ticket.Principal.Identity;

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

            // Store the "usage" property as a claim.
            identity.AddClaim(OpenIdConnectConstants.Claims.TokenUsage, OpenIdConnectConstants.TokenUsages.IdToken);

            // Store the "unique_id" property as a claim.
            identity.AddClaim(OpenIdConnectConstants.Claims.JwtId, ticket.GetTokenId());

            // Store the "confidentiality_level" property as a claim.
            var confidentiality = ticket.GetProperty(OpenIdConnectConstants.Properties.ConfidentialityLevel);
            if (!string.IsNullOrEmpty(confidentiality))
            {
                identity.AddClaim(OpenIdConnectConstants.Claims.ConfidentialityLevel, confidentiality);
            }

            // Store the audiences as claims.
            foreach (var audience in notification.Audiences)
            {
                identity.AddClaim(OpenIdConnectConstants.Claims.Audience, audience);
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
                identity.AddClaim(OpenIdConnectConstants.Claims.Nonce, nonce);
            }

            if (notification.SigningCredentials != null && (!string.IsNullOrEmpty(response.Code) ||
                                                            !string.IsNullOrEmpty(response.AccessToken)))
            {
                using (var algorithm = OpenIdConnectServerHelpers.GetHashAlgorithm(notification.SigningCredentials.Algorithm))
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

            var token = notification.SecurityTokenHandler.CreateEncodedJwt(new SecurityTokenDescriptor
            {
                Subject = identity,
                Issuer = notification.Issuer,
                EncryptingCredentials = notification.EncryptingCredentials,
                SigningCredentials = notification.SigningCredentials,
                IssuedAt = notification.Ticket.Properties.IssuedUtc?.UtcDateTime,
                NotBefore = notification.Ticket.Properties.IssuedUtc?.UtcDateTime,
                Expires = notification.Ticket.Properties.ExpiresUtc?.UtcDateTime
            });

            Logger.LogTrace("A new identity token was successfully generated using the specified " +
                            "security token handler: {Token} ; {Claims} ; {Properties}.",
                            token, ticket.Principal.Claims, ticket.Properties.Items);

            return token;
        }

        private async Task<string> SerializeRefreshTokenAsync(
            ClaimsPrincipal principal, AuthenticationProperties properties,
            OpenIdConnectRequest request, OpenIdConnectResponse response)
        {
            // Note: claims in refresh tokens are never filtered as they are supposed to be opaque:
            // SerializeAccessTokenAsync and SerializeIdentityTokenAsync are responsible of ensuring
            // that subsequent access and identity tokens are correctly filtered.

            // Create a new ticket containing the updated properties.
            var ticket = new AuthenticationTicket(principal, properties, Scheme.Name);
            ticket.Properties.IssuedUtc = Options.SystemClock.UtcNow;

            // Only set the expiration date if a lifetime was specified in either the ticket or the options.
            var lifetime = ticket.GetRefreshTokenLifetime() ?? Options.RefreshTokenLifetime;
            if (lifetime.HasValue)
            {
                ticket.Properties.ExpiresUtc = ticket.Properties.IssuedUtc + lifetime.Value;
            }

            // Associate a random identifier with the refresh token.
            ticket.SetTokenId(Guid.NewGuid().ToString());

            // Remove the unwanted properties from the authentication ticket.
            ticket.RemoveProperty(OpenIdConnectConstants.Properties.AuthorizationCodeLifetime)
                  .RemoveProperty(OpenIdConnectConstants.Properties.CodeChallenge)
                  .RemoveProperty(OpenIdConnectConstants.Properties.CodeChallengeMethod)
                  .RemoveProperty(OpenIdConnectConstants.Properties.Nonce)
                  .RemoveProperty(OpenIdConnectConstants.Properties.OriginalRedirectUri)
                  .RemoveProperty(OpenIdConnectConstants.Properties.TokenUsage);

            var notification = new SerializeRefreshTokenContext(Context, Scheme, Options, request, response, ticket)
            {
                DataFormat = Options.RefreshTokenFormat
            };

            await Provider.SerializeRefreshToken(notification);

            if (notification.IsHandled || !string.IsNullOrEmpty(notification.RefreshToken))
            {
                return notification.RefreshToken;
            }

            if (notification.DataFormat == null)
            {
                throw new InvalidOperationException("A data formatter must be provided.");
            }

            var result = notification.DataFormat.Protect(ticket);

            Logger.LogTrace("A new refresh token was successfully generated using the " +
                            "specified data format: {Token} ; {Claims} ; {Properties}.",
                            result, ticket.Principal.Claims, ticket.Properties.Items);

            return result;
        }

        private async Task<AuthenticationTicket> DeserializeAuthorizationCodeAsync(string code, OpenIdConnectRequest request)
        {
            var notification = new DeserializeAuthorizationCodeContext(Context, Scheme, Options, request, code)
            {
                DataFormat = Options.AuthorizationCodeFormat
            };

            await Provider.DeserializeAuthorizationCode(notification);

            if (notification.IsHandled || notification.Ticket != null)
            {
                notification.Ticket?.SetTokenUsage(OpenIdConnectConstants.TokenUsages.AuthorizationCode);

                return notification.Ticket;
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

            // Note: since the data formatter relies on a data protector using different "purposes" strings
            // per token type, the ticket returned by Unprotect() is guaranteed to be an authorization code.
            ticket.SetTokenUsage(OpenIdConnectConstants.TokenUsages.AuthorizationCode);

            Logger.LogTrace("The authorization code '{Code}' was successfully validated using " +
                            "the specified token data format: {Claims} ; {Properties}.",
                            code, ticket.Principal.Claims, ticket.Properties.Items);

            return ticket;
        }

        private async Task<AuthenticationTicket> DeserializeAccessTokenAsync(string token, OpenIdConnectRequest request)
        {
            var notification = new DeserializeAccessTokenContext(Context, Scheme, Options, request, token)
            {
                DataFormat = Options.AccessTokenFormat,
                SecurityTokenHandler = Options.AccessTokenHandler
            };

            // Note: ValidateAudience and ValidateLifetime are always set to false:
            // if necessary, the audience and the expiration can be validated
            // in InvokeIntrospectionEndpointAsync or InvokeTokenEndpointAsync.
            notification.TokenValidationParameters = new TokenValidationParameters
            {
                IssuerSigningKeys = Options.SigningCredentials.Select(credentials => credentials.Key),
                NameClaimType = OpenIdConnectConstants.Claims.Name,
                RoleClaimType = OpenIdConnectConstants.Claims.Role,
                TokenDecryptionKeys = Options.EncryptingCredentials.Select(credentials => credentials.Key)
                                                                   .Where(key => key is SymmetricSecurityKey),
                ValidIssuer = Context.GetIssuer(Options),
                ValidateAudience = false,
                ValidateLifetime = false
            };

            await Provider.DeserializeAccessToken(notification);

            if (notification.IsHandled || notification.Ticket != null)
            {
                notification.Ticket?.SetTokenUsage(OpenIdConnectConstants.TokenUsages.AccessToken);

                return notification.Ticket;
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
                    Logger.LogTrace("The received token was invalid or malformed: {Token}.", token);

                    return null;
                }

                // Note: since the data formatter relies on a data protector using different "purposes" strings
                // per token type, the ticket returned by Unprotect() is guaranteed to be an access token.
                value.SetTokenUsage(OpenIdConnectConstants.TokenUsages.AccessToken);

                Logger.LogTrace("The access token '{Token}' was successfully validated using " +
                                "the specified token data format: {Claims} ; {Properties}.",
                                token, value.Principal.Claims, value.Properties.Items);

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

            var ticket = new AuthenticationTicket(principal, properties, Scheme.Name)
                .SetAudiences(principal.FindAll(OpenIdConnectConstants.Claims.Audience).Select(claim => claim.Value))
                .SetConfidentialityLevel(principal.GetClaim(OpenIdConnectConstants.Claims.ConfidentialityLevel))
                .SetPresenters(principal.FindAll(OpenIdConnectConstants.Claims.AuthorizedParty).Select(claim => claim.Value))
                .SetScopes(principal.FindAll(OpenIdConnectConstants.Claims.Scope).Select(claim => claim.Value))
                .SetTokenId(principal.GetClaim(OpenIdConnectConstants.Claims.JwtId))
                .SetTokenUsage(principal.GetClaim(OpenIdConnectConstants.Claims.TokenUsage));

            // Ensure that the received ticket is an access token.
            if (!ticket.IsAccessToken())
            {
                Logger.LogTrace("The received token was not an access token: {Token}.", token);

                return null;
            }

            Logger.LogTrace("The access token '{Token}' was successfully validated using " +
                            "the specified security token handler: {Claims} ; {Properties}.",
                            token, ticket.Principal.Claims, ticket.Properties.Items);

            return ticket;
        }

        private async Task<AuthenticationTicket> DeserializeIdentityTokenAsync(string token, OpenIdConnectRequest request)
        {
            var notification = new DeserializeIdentityTokenContext(Context, Scheme, Options, request, token)
            {
                SecurityTokenHandler = Options.IdentityTokenHandler
            };

            // Note: ValidateAudience and ValidateLifetime are always set to false:
            // if necessary, the audience and the expiration can be validated
            // in InvokeIntrospectionEndpointAsync or InvokeTokenEndpointAsync.
            notification.TokenValidationParameters = new TokenValidationParameters
            {
                IssuerSigningKeys = Options.SigningCredentials.Select(credentials => credentials.Key)
                                                              .Where(key => key is AsymmetricSecurityKey),

                NameClaimType = OpenIdConnectConstants.Claims.Name,
                RoleClaimType = OpenIdConnectConstants.Claims.Role,
                ValidIssuer = Context.GetIssuer(Options),
                ValidateAudience = false,
                ValidateLifetime = false
            };

            await Provider.DeserializeIdentityToken(notification);

            if (notification.IsHandled || notification.Ticket != null)
            {
                notification.Ticket?.SetTokenUsage(OpenIdConnectConstants.TokenUsages.IdToken);

                return notification.Ticket;
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

            var ticket = new AuthenticationTicket(principal, properties, Scheme.Name)
                .SetAudiences(principal.FindAll(OpenIdConnectConstants.Claims.Audience).Select(claim => claim.Value))
                .SetConfidentialityLevel(principal.GetClaim(OpenIdConnectConstants.Claims.ConfidentialityLevel))
                .SetPresenters(principal.FindAll(OpenIdConnectConstants.Claims.AuthorizedParty).Select(claim => claim.Value))
                .SetTokenId(principal.GetClaim(OpenIdConnectConstants.Claims.JwtId))
                .SetTokenUsage(principal.GetClaim(OpenIdConnectConstants.Claims.TokenUsage));

            // Ensure that the received ticket is an identity token.
            if (!ticket.IsIdentityToken())
            {
                Logger.LogTrace("The received token was not an identity token: {Token}.", token);

                return null;
            }

            Logger.LogTrace("The identity token '{Token}' was successfully validated using " +
                            "the specified security token handler: {Claims} ; {Properties}.",
                            token, ticket.Principal.Claims, ticket.Properties.Items);

            return ticket;
        }

        private async Task<AuthenticationTicket> DeserializeRefreshTokenAsync(string token, OpenIdConnectRequest request)
        {
            var notification = new DeserializeRefreshTokenContext(Context, Scheme, Options, request, token)
            {
                DataFormat = Options.RefreshTokenFormat
            };

            await Provider.DeserializeRefreshToken(notification);

            if (notification.IsHandled || notification.Ticket != null)
            {
                notification.Ticket?.SetTokenUsage(OpenIdConnectConstants.TokenUsages.RefreshToken);

                return notification.Ticket;
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

            // Note: since the data formatter relies on a data protector using different "purposes" strings
            // per token type, the ticket returned by Unprotect() is guaranteed to be a refresh token.
            ticket.SetTokenUsage(OpenIdConnectConstants.TokenUsages.RefreshToken);

            Logger.LogTrace("The refresh token '{Token}' was successfully validated using " +
                            "the specified token data format: {Claims} ; {Properties}.",
                            token, ticket.Principal.Claims, ticket.Properties.Items);

            return ticket;
        }
    }
}
