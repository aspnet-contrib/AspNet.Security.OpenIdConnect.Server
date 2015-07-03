/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */
 
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using Microsoft.IdentityModel.Protocols;

namespace Owin.Security.OpenIdConnect.Extensions {
    /// <summary>
    /// Provides extension methods to make <see cref="OpenIdConnectMessage"/>
    /// easier to work with, specially in server-side scenarios.
    /// </summary>
    public static class OpenIdConnectExtensions {
        /// <summary>
        /// True if the "response_type" parameter
        /// corresponds to the authorization code flow.
        /// See http://tools.ietf.org/html/rfc6749#section-4.1.1
        /// </summary>
        public static bool IsAuthorizationCodeFlow(this OpenIdConnectMessage message) {
            if (message == null) {
                throw new ArgumentNullException("message");
            }

            return string.Equals(message.ResponseType, OpenIdConnectConstants.ResponseTypes.Code, StringComparison.Ordinal);
        }

        /// <summary>
        /// True if the "response_type" parameter
        /// corresponds to the implicit flow.
        /// See http://tools.ietf.org/html/rfc6749#section-4.2.1 and
        /// http://openid.net/specs/openid-connect-core-1_0.html
        /// </summary>
        public static bool IsImplicitFlow(this OpenIdConnectMessage message) {
            if (message == null) {
                throw new ArgumentNullException("message");
            }

            // Note: while the OIDC specs do not reuse the OAuth2-inherited response_type=token,
            // it is considered as a valid response_type for the implicit flow, even for pure OIDC requests.
            return SetEquals(message.ResponseType, OpenIdConnectConstants.ResponseTypes.IdToken) ||

                   SetEquals(message.ResponseType, OpenIdConnectConstants.ResponseTypes.Token) ||

                   SetEquals(message.ResponseType, OpenIdConnectConstants.ResponseTypes.IdToken,
                                                   OpenIdConnectConstants.ResponseTypes.Token);
        }

        /// <summary>
        /// True if the "response_type" parameter
        /// corresponds to the hybrid flow.
        /// See http://tools.ietf.org/html/rfc6749#section-4.2.1 and
        /// http://openid.net/specs/openid-connect-core-1_0.html
        /// </summary>
        public static bool IsHybridFlow(this OpenIdConnectMessage message) {
            if (message == null) {
                throw new ArgumentNullException("message");
            }

            return SetEquals(message.ResponseType, OpenIdConnectConstants.ResponseTypes.Code,
                                                   OpenIdConnectConstants.ResponseTypes.IdToken) ||

                   SetEquals(message.ResponseType, OpenIdConnectConstants.ResponseTypes.Code,
                                                   OpenIdConnectConstants.ResponseTypes.Token) ||
                                                   
                   SetEquals(message.ResponseType, OpenIdConnectConstants.ResponseTypes.Code,
                                                   OpenIdConnectConstants.ResponseTypes.IdToken,
                                                   OpenIdConnectConstants.ResponseTypes.Token);
        }

        /// <summary>
        /// True if the "response_mode" parameter is "fragment" or if
        /// fragment is the default mode for the response_type received.
        /// See http://openid.net/specs/oauth-v2-multiple-response-types-1_0.html
        /// </summary>
        public static bool IsFragmentResponseMode(this OpenIdConnectMessage message) {
            if (message == null) {
                throw new ArgumentNullException("message");
            }

            if (string.Equals(message.ResponseMode, OpenIdConnectConstants.ResponseModes.Fragment, StringComparison.Ordinal)) {
                return true;
            }

            // Don't guess the response_mode value
            // if an explicit value has ben provided.
            if (!string.IsNullOrEmpty(message.ResponseMode)) {
                return false;
            }

            // Both the implicit and the hybrid flows
            // use response_mode=fragment by default.
            return message.IsImplicitFlow() || message.IsHybridFlow();
        }

        /// <summary>
        /// True if the "response_mode" parameter is "query" or if
        /// query is the default mode for the response_type received.
        /// See http://openid.net/specs/oauth-v2-multiple-response-types-1_0.html
        /// </summary>
        public static bool IsQueryResponseMode(this OpenIdConnectMessage message) {
            if (message == null) {
                throw new ArgumentNullException("message");
            }

            if (string.Equals(message.ResponseMode, OpenIdConnectConstants.ResponseModes.Query, StringComparison.Ordinal)) {
                return true;
            }

            // Don't guess the response_mode value
            // if an explicit value has ben provided.
            if (!string.IsNullOrEmpty(message.ResponseMode)) {
                return false;
            }

            // The code flow uses response_mode=query by default.
            return message.IsAuthorizationCodeFlow();
        }

        /// <summary>
        /// True if the "response_mode" parameter is "form_post".
        /// See http://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html
        /// </summary>
        public static bool IsFormPostResponseMode(this OpenIdConnectMessage message) {
            if (message == null) {
                throw new ArgumentNullException("message");
            }

            return string.Equals(message.ResponseMode, OpenIdConnectConstants.ResponseModes.FormPost, StringComparison.Ordinal);
        }

        /// <summary>
        /// True when the "grant_type" is "authorization_code".
        /// See also http://tools.ietf.org/html/rfc6749#section-4.1.3
        /// </summary>    
        public static bool IsAuthorizationCodeGrantType(this OpenIdConnectMessage message) {
            if (message == null) {
                throw new ArgumentNullException("message");
            }

            return string.Equals(message.GrantType, OpenIdConnectConstants.GrantTypes.AuthorizationCode, StringComparison.Ordinal);
        }

        /// <summary>
        /// True when the "grant_type" is "client_credentials".
        /// See also http://tools.ietf.org/html/rfc6749#section-4.4.2
        /// </summary>  
        public static bool IsClientCredentialsGrantType(this OpenIdConnectMessage message) {
            if (message == null) {
                throw new ArgumentNullException("message");
            }

            return string.Equals(message.GrantType, OpenIdConnectConstants.GrantTypes.ClientCredentials, StringComparison.Ordinal);
        }

        /// <summary>
        /// True when the "grant_type" is "refresh_token".
        /// See also http://tools.ietf.org/html/rfc6749#section-6
        /// </summary>    
        public static bool IsRefreshTokenGrantType(this OpenIdConnectMessage message) {
            if (message == null) {
                throw new ArgumentNullException("message");
            }

            return string.Equals(message.GrantType, OpenIdConnectConstants.GrantTypes.RefreshToken, StringComparison.Ordinal);
        }

        /// <summary>
        /// True when the "grant_type" is "password".
        /// See also http://tools.ietf.org/html/rfc6749#section-4.3.2
        /// </summary>    
        public static bool IsPasswordGrantType(this OpenIdConnectMessage message) {
            if (message == null) {
                throw new ArgumentNullException("message");
            }

            return string.Equals(message.GrantType, OpenIdConnectConstants.GrantTypes.Password, StringComparison.Ordinal);
        }

        /// <summary>
        /// Determines whether the response_type exposed by the
        /// <paramref name="message"/> contains the given <paramref name="component"/> or not.
        /// </summary>
        /// <param name="message">The <see cref="OpenIdConnectMessage"/> instance.</param>
        /// <param name="component">The component to look for in the parameter.</param>
        public static bool ContainsResponseType(this OpenIdConnectMessage message, string component) {
            if (message == null) {
                throw new ArgumentNullException("message");
            }

            return HasValue(message.ResponseType, component);
        }

        /// <summary>
        /// Determines whether the scope exposed by the <paramref name="message"/>
        /// contains the given <paramref name="component"/> or not.
        /// </summary>
        /// <param name="message">The <see cref="OpenIdConnectMessage"/> instance.</param>
        /// <param name="component">The component to look for in the parameter.</param>
        public static bool ContainsScope(this OpenIdConnectMessage message, string component) {
            if (message == null) {
                throw new ArgumentNullException("message");
            }

            return HasValue(message.Scope, component);
        }

        /// <summary>
        /// Determines whether the <paramref name="parameter"/> exposed by the
        /// <paramref name="message"/> contains the given <paramref name="component"/> or not.
        /// </summary>
        /// <param name="message">The <see cref="OpenIdConnectMessage"/> instance.</param>
        /// <param name="parameter">The parameter to search in.</param>
        /// <param name="component">The component to look for in the parameter.</param>
        public static bool HasComponent(this OpenIdConnectMessage message,
            Func<OpenIdConnectMessage, string> parameter, string component) {
            if (message == null) {
                throw new ArgumentNullException("message");
            }

            if (parameter == null) {
                throw new ArgumentNullException("parameter");
            }

            return HasValue(source: parameter(message), value: component);
        }

        /// <summary>
        /// Extracts the unique identifier associated with an <see cref="OpenIdConnectMessage"/>.
        /// </summary>
        /// <param name="message">The <see cref="OpenIdConnectMessage"/> instance.</param>
        public static string GetUniqueIdentifier(this OpenIdConnectMessage message) {
            if (message == null) {
                throw new ArgumentNullException("message");
            }

            return message.GetParameter("unique_id");
        }

        /// <summary>
        /// Extracts the refresh token from an <see cref="OpenIdConnectMessage"/>.
        /// </summary>
        /// <param name="message">The <see cref="OpenIdConnectMessage"/> instance.</param>
        public static string GetRefreshToken(this OpenIdConnectMessage message) {
            if (message == null) {
                throw new ArgumentNullException("message");
            }

            return message.GetParameter("refresh_token");
        }

        /// <summary>
        /// Extracts the audiences from an <see cref="OpenIdConnectMessage"/>.
        /// </summary>
        /// <param name="message">The <see cref="OpenIdConnectMessage"/> instance.</param>
        public static IEnumerable<string> GetAudiences(this OpenIdConnectMessage message) {
            if (message == null) {
                throw new ArgumentNullException("message");
            }

            var audience = message.GetParameter("audience");
            if (string.IsNullOrEmpty(audience)) {
                return Enumerable.Empty<string>();
            }

            return audience.Split(' ');
        }

        /// <summary>
        /// Extracts the resources from an <see cref="OpenIdConnectMessage"/>.
        /// </summary>
        /// <param name="message">The <see cref="OpenIdConnectMessage"/> instance.</param>
        public static IEnumerable<string> GetResources(this OpenIdConnectMessage message) {
            if (message == null) {
                throw new ArgumentNullException("message");
            }

            var resource = message.Resource;
            if (string.IsNullOrEmpty(resource)) {
                return Enumerable.Empty<string>();
            }
            
            return resource.Split(' ');
        }

        /// <summary>
        /// Extracts the scopes from an <see cref="OpenIdConnectMessage"/>.
        /// </summary>
        /// <param name="message">The <see cref="OpenIdConnectMessage"/> instance.</param>
        public static IEnumerable<string> GetScopes(this OpenIdConnectMessage message) {
            if (message == null) {
                throw new ArgumentNullException("message");
            }

            var scope = message.Scope;
            if (string.IsNullOrEmpty(scope)) {
                return Enumerable.Empty<string>();
            }

            return scope.Split(' ');
        }

        /// <summary>
        /// Adds a unique identifier to a given <see cref="OpenIdConnectMessage"/>.
        /// </summary>
        /// <param name="message">The <see cref="OpenIdConnectMessage"/> instance.</param>
        /// <param name="identifier">The unique identifier.</param>
        public static OpenIdConnectMessage SetUniqueIdentifier(this OpenIdConnectMessage message, string identifier) {
            if (message == null) {
                throw new ArgumentNullException("message");
            }

            if (string.IsNullOrEmpty(identifier)) {
                throw new ArgumentNullException("identifier");
            }

            message.SetParameter("unique_id", identifier);
            return message;
        }

        /// <summary>
        /// Adds a refresh token to a given <see cref="OpenIdConnectMessage"/>.
        /// </summary>
        /// <param name="message">The <see cref="OpenIdConnectMessage"/> instance.</param>
        /// <param name="token">The refresh token.</param>
        public static OpenIdConnectMessage SetRefreshToken(this OpenIdConnectMessage message, string token) {
            if (message == null) {
                throw new ArgumentNullException("message");
            }

            if (string.IsNullOrEmpty(token)) {
                throw new ArgumentNullException("token");
            }

            message.SetParameter("refresh_token", token);
            return message;
        }

        /// <summary>
        /// Determines whether the given claim contains a destination.
        /// </summary>
        /// <param name="claim">The <see cref="Claim"/> instance.</param>
        public static bool HasDestination(this Claim claim) {
            if (claim == null) {
                throw new ArgumentNullException("claim");
            }

            return claim.Properties.ContainsKey("destination");
        }

        /// <summary>
        /// Determines whether the given claim
        /// contains the required destination.
        /// </summary>
        /// <param name="claim">The <see cref="Claim"/> instance.</param>
        /// <param name="value">The required destination.</param>
        public static bool HasDestination(this Claim claim, string value) {
            if (claim == null) {
                throw new ArgumentNullException("claim");
            }

            if (string.IsNullOrEmpty(value)) {
                throw new ArgumentNullException("value");
            }

            string destination;
            if (!claim.Properties.TryGetValue("destination", out destination)) {
                return false;
            }

            return HasValue(destination, value);
        }

        /// <summary>
        /// Adds a specific destination to a claim.
        /// </summary>
        /// <param name="claim">The <see cref="Claim"/> instance.</param>
        /// <param name="value">The destination.</param>
        public static Claim WithDestination(this Claim claim, string value) {
            if (claim == null) {
                throw new ArgumentNullException("claim");
            }

            if (string.IsNullOrEmpty(value)) {
                throw new ArgumentNullException("value");
            }

            string destination;
            if (claim.Properties.TryGetValue("destination", out destination)) {
                claim.Properties["destination"] = string.Concat(destination, ' ', value);
                return claim;
            }

            claim.Properties.Add("destination", value);
            return claim;
        }

        /// <summary>
        /// Clones an identity by filtering its claims and the claims of its actor, recursively.
        /// </summary>
        /// <param name="identity">The <see cref="ClaimsIdentity"/> instance to filter.</param>
        /// <param name="filter">
        /// The delegate filtering the claims: return <c>true</c>
        /// to accept the claim, <c>false</c> to remove it.
        /// </param>
        public static ClaimsIdentity Clone(this ClaimsIdentity identity, Func<Claim, bool> filter) {
            var clone = identity.Clone();

            foreach (var claim in clone.Claims.ToArray()) {
                if (!filter(claim)) {
                    clone.RemoveClaim(claim);
                }
            }

            if (clone.Actor != null) {
                clone.Actor = clone.Actor.Clone(filter);
            }

            return clone;
        }

        /// <summary>
        /// Clones a principal by filtering its identities.
        /// </summary>
        /// <param name="principal">The <see cref="ClaimsPrincipal"/> instance to filter.</param>
        /// <param name="filter">
        /// The delegate filtering the claims: return <c>true</c>
        /// to accept the claim, <c>false</c> to remove it.
        /// </param>
        public static ClaimsPrincipal Clone(this ClaimsPrincipal principal, Func<Claim, bool> filter) {
            var clone = new ClaimsPrincipal();

            foreach (var identity in principal.Identities) {
                clone.AddIdentity(identity.Clone(filter));
            }

            return clone;
        }

        /// <summary>
        /// Adds a claim to a given identity.
        /// </summary>
        /// <param name="identity">The identity.</param>
        /// <param name="type">The type associated with the claim.</param>
        /// <param name="value">The value associated with the claim.</param>
        public static ClaimsIdentity AddClaim(this ClaimsIdentity identity, string type, string value) {
            if (identity == null) {
                throw new ArgumentNullException("identity");
            }

            identity.AddClaim(new Claim(type, value));
            return identity;
        }

        /// <summary>
        /// Adds a claim to a given identity.
        /// </summary>
        /// <param name="identity">The identity.</param>
        /// <param name="type">The type associated with the claim.</param>
        /// <param name="value">The value associated with the claim.</param>
        /// <param name="destination">The destination associated with the claim.</param>
        public static ClaimsIdentity AddClaim(this ClaimsIdentity identity, string type, string value, string destination) {
            if (identity == null) {
                throw new ArgumentNullException("identity");
            }

            identity.AddClaim(new Claim(type, value).WithDestination(destination));
            return identity;
        }

        private static bool HasValue(string source, string value) {
            if (string.IsNullOrEmpty(source)) {
                return false;
            }

            return (from component in source.Split(' ')
                    where string.Equals(component, value, StringComparison.Ordinal)
                    select component).Any();
        }

        private static bool SetEquals(string source, params string[] components) {
            if (string.IsNullOrEmpty(source)) {
                return false;
            }

            if (components == null || !components.Any()) {
                return false;
            }

            var set = new HashSet<string>(
                collection: source.Split(' '),
                comparer: StringComparer.Ordinal);

            return set.SetEquals(components);
        }
    }
}
