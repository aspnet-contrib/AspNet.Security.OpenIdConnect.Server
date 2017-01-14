/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.Linq;
using JetBrains.Annotations;

namespace AspNet.Security.OpenIdConnect.Primitives {
    /// <summary>
    /// Provides extension methods to make <see cref="OpenIdConnectRequest"/>
    /// and <see cref="OpenIdConnectResponse"/> easier to work with.
    /// </summary>
    public static class OpenIdConnectExtensions {
        /// <summary>
        /// Extracts the resources from an <see cref="OpenIdConnectRequest"/>.
        /// </summary>
        /// <param name="request">The <see cref="OpenIdConnectRequest"/> instance.</param>
        public static IEnumerable<string> GetResources([NotNull] this OpenIdConnectRequest request) {
            if (request == null) {
                throw new ArgumentNullException(nameof(request));
            }

            return request.Resource?.Split(OpenIdConnectConstants.Separators.Space, StringSplitOptions.RemoveEmptyEntries)
                                   ?.Distinct(StringComparer.Ordinal)
                   ?? Enumerable.Empty<string>();
        }

        /// <summary>
        /// Extracts the scopes from an <see cref="OpenIdConnectRequest"/>.
        /// </summary>
        /// <param name="request">The <see cref="OpenIdConnectRequest"/> instance.</param>
        public static IEnumerable<string> GetScopes([NotNull] this OpenIdConnectRequest request) {
            if (request == null) {
                throw new ArgumentNullException(nameof(request));
            }

            return request.Scope?.Split(OpenIdConnectConstants.Separators.Space, StringSplitOptions.RemoveEmptyEntries)
                                ?.Distinct(StringComparer.Ordinal)
                   ?? Enumerable.Empty<string>();
        }

        /// <summary>
        /// Determines whether the response_type exposed by the
        /// <paramref name="request"/> contains the given <paramref name="component"/> or not.
        /// </summary>
        /// <param name="request">The <see cref="OpenIdConnectRequest"/> instance.</param>
        /// <param name="component">The component to look for in the parameter.</param>
        public static bool HasResponseType([NotNull] this OpenIdConnectRequest request, string component) {
            if (request == null) {
                throw new ArgumentNullException(nameof(request));
            }

            return HasValue(request.ResponseType, component);
        }

        /// <summary>
        /// Determines whether the scope exposed by the <paramref name="request"/>
        /// contains the given <paramref name="component"/> or not.
        /// </summary>
        /// <param name="request">The <see cref="OpenIdConnectRequest"/> instance.</param>
        /// <param name="component">The component to look for in the parameter.</param>
        public static bool HasScope([NotNull] this OpenIdConnectRequest request, string component) {
            if (request == null) {
                throw new ArgumentNullException(nameof(request));
            }

            return HasValue(request.Scope, component);
        }

        /// <summary>
        /// Determines whether the given request is an authorization request.
        /// </summary>
        /// <param name="request">The <see cref="OpenIdConnectRequest"/> instance.</param>
        /// <returns><c>true</c> if the request is an authorization request, <c>false</c> otherwise.</returns>
        public static bool IsAuthorizationRequest([NotNull] this OpenIdConnectRequest request) {
            if (request == null) {
                throw new ArgumentNullException(nameof(request));
            }

            var value = request.GetProperty<string>(OpenIdConnectConstants.Properties.MessageType);
            if (string.IsNullOrEmpty(value)) {
                return false;
            }

            return string.Equals(value, OpenIdConnectConstants.MessageTypes.Authorization, StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Determines whether the request was transmitted using a confidential channel
        /// (i.e if the transaction was only visible by the client and if client authentication was enforced).
        /// </summary>
        /// <param name="request">The <see cref="OpenIdConnectRequest"/> instance.</param>
        /// <returns><c>true</c> if the request is a configuration request, <c>false</c> otherwise.</returns>
        public static bool IsConfidential([NotNull] this OpenIdConnectRequest request) {
            if (request == null) {
                throw new ArgumentNullException(nameof(request));
            }

            var value = request.GetProperty<string>(OpenIdConnectConstants.Properties.ConfidentialityLevel);
            if (string.IsNullOrEmpty(value)) {
                return false;
            }

            return string.Equals(value, OpenIdConnectConstants.ConfidentialityLevels.Private, StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Determines whether the given request is a configuration request.
        /// </summary>
        /// <param name="request">The <see cref="OpenIdConnectRequest"/> instance.</param>
        /// <returns><c>true</c> if the request is a configuration request, <c>false</c> otherwise.</returns>
        public static bool IsConfigurationRequest([NotNull] this OpenIdConnectRequest request) {
            if (request == null) {
                throw new ArgumentNullException(nameof(request));
            }

            var value = request.GetProperty<string>(OpenIdConnectConstants.Properties.MessageType);
            if (string.IsNullOrEmpty(value)) {
                return false;
            }

            return string.Equals(value, OpenIdConnectConstants.MessageTypes.Configuration, StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Determines whether the given request is a cryptography request.
        /// </summary>
        /// <param name="request">The <see cref="OpenIdConnectRequest"/> instance.</param>
        /// <returns><c>true</c> if the request is a cryptography request, <c>false</c> otherwise.</returns>
        public static bool IsCryptographyRequest([NotNull] this OpenIdConnectRequest request) {
            if (request == null) {
                throw new ArgumentNullException(nameof(request));
            }

            var value = request.GetProperty<string>(OpenIdConnectConstants.Properties.MessageType);
            if (string.IsNullOrEmpty(value)) {
                return false;
            }

            return string.Equals(value, OpenIdConnectConstants.MessageTypes.Cryptography, StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Determines whether the given request is an introspection request.
        /// </summary>
        /// <param name="request">The <see cref="OpenIdConnectRequest"/> instance.</param>
        /// <returns><c>true</c> if the request is an introspection request, <c>false</c> otherwise.</returns>
        public static bool IsIntrospectionRequest([NotNull] this OpenIdConnectRequest request) {
            if (request == null) {
                throw new ArgumentNullException(nameof(request));
            }

            var value = request.GetProperty<string>(OpenIdConnectConstants.Properties.MessageType);
            if (string.IsNullOrEmpty(value)) {
                return false;
            }

            return string.Equals(value, OpenIdConnectConstants.MessageTypes.Introspection, StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Determines whether the given request is a logout request.
        /// </summary>
        /// <param name="request">The <see cref="OpenIdConnectRequest"/> instance.</param>
        /// <returns><c>true</c> if the request is a logout request, <c>false</c> otherwise.</returns>
        public static bool IsLogoutRequest([NotNull] this OpenIdConnectRequest request) {
            if (request == null) {
                throw new ArgumentNullException(nameof(request));
            }

            var value = request.GetProperty<string>(OpenIdConnectConstants.Properties.MessageType);
            if (string.IsNullOrEmpty(value)) {
                return false;
            }

            return string.Equals(value, OpenIdConnectConstants.MessageTypes.Logout, StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Determines whether the given request is a revocation request.
        /// </summary>
        /// <param name="request">The <see cref="OpenIdConnectRequest"/> instance.</param>
        /// <returns><c>true</c> if the request is a revocation request, <c>false</c> otherwise.</returns>
        public static bool IsRevocationRequest([NotNull] this OpenIdConnectRequest request) {
            if (request == null) {
                throw new ArgumentNullException(nameof(request));
            }

            var value = request.GetProperty<string>(OpenIdConnectConstants.Properties.MessageType);
            if (string.IsNullOrEmpty(value)) {
                return false;
            }

            return string.Equals(value, OpenIdConnectConstants.MessageTypes.Revocation, StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Determines whether the given request is a token request.
        /// </summary>
        /// <param name="request">The <see cref="OpenIdConnectRequest"/> instance.</param>
        /// <returns><c>true</c> if the request is a token request, <c>false</c> otherwise.</returns>
        public static bool IsTokenRequest([NotNull] this OpenIdConnectRequest request) {
            if (request == null) {
                throw new ArgumentNullException(nameof(request));
            }

            var value = request.GetProperty<string>(OpenIdConnectConstants.Properties.MessageType);
            if (string.IsNullOrEmpty(value)) {
                return false;
            }

            return string.Equals(value, OpenIdConnectConstants.MessageTypes.Token, StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Determines whether the given request is a userinfo request.
        /// </summary>
        /// <param name="request">The <see cref="OpenIdConnectRequest"/> instance.</param>
        /// <returns><c>true</c> if the request is a userinfo request, <c>false</c> otherwise.</returns>
        public static bool IsUserinfoRequest([NotNull] this OpenIdConnectRequest request) {
            if (request == null) {
                throw new ArgumentNullException(nameof(request));
            }

            var value = request.GetProperty<string>(OpenIdConnectConstants.Properties.MessageType);
            if (string.IsNullOrEmpty(value)) {
                return false;
            }

            return string.Equals(value, OpenIdConnectConstants.MessageTypes.Userinfo, StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Determines whether the "response_type" parameter corresponds to the "none" response type.
        /// See http://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#none for more information.
        /// </summary>
        /// <param name="request">The <see cref="OpenIdConnectRequest"/> instance.</param>
        /// <returns><c>true</c> if the request is a response_type=none request, <c>false</c> otherwise.</returns>
        public static bool IsNoneFlow([NotNull] this OpenIdConnectRequest request) {
            if (request == null) {
                throw new ArgumentNullException(nameof(request));
            }

            return string.Equals(request.ResponseType?.Trim(), OpenIdConnectConstants.ResponseTypes.None, StringComparison.Ordinal);
        }

        /// <summary>
        /// Determines whether the "response_type" parameter corresponds to the authorization code flow.
        /// See http://tools.ietf.org/html/rfc6749#section-4.1.1 for more information.
        /// </summary>
        /// <param name="request">The <see cref="OpenIdConnectRequest"/> instance.</param>
        /// <returns><c>true</c> if the request is a code flow request, <c>false</c> otherwise.</returns>
        public static bool IsAuthorizationCodeFlow([NotNull] this OpenIdConnectRequest request) {
            if (request == null) {
                throw new ArgumentNullException(nameof(request));
            }

            return string.Equals(request.ResponseType?.Trim(), OpenIdConnectConstants.ResponseTypes.Code, StringComparison.Ordinal);
        }

        /// <summary>
        /// Determines whether the "response_type" parameter corresponds to the implicit flow.
        /// See http://tools.ietf.org/html/rfc6749#section-4.2.1 and
        /// http://openid.net/specs/openid-connect-core-1_0.html for more information
        /// </summary>
        /// <param name="request">The <see cref="OpenIdConnectRequest"/> instance.</param>
        /// <returns><c>true</c> if the request is an implicit flow request, <c>false</c> otherwise.</returns>
        public static bool IsImplicitFlow([NotNull] this OpenIdConnectRequest request) {
            if (request == null) {
                throw new ArgumentNullException(nameof(request));
            }

            // Note: while the OIDC specs do not reuse the OAuth2-inherited response_type=token,
            // it is considered as a valid response_type for the implicit flow, even for pure OIDC requests.
            return SetEquals(request.ResponseType, OpenIdConnectConstants.ResponseTypes.IdToken) ||

                   SetEquals(request.ResponseType, OpenIdConnectConstants.ResponseTypes.Token) ||

                   SetEquals(request.ResponseType, OpenIdConnectConstants.ResponseTypes.IdToken,
                                                   OpenIdConnectConstants.ResponseTypes.Token);
        }

        /// <summary>
        /// Determines whether the "response_type" parameter corresponds to the hybrid flow.
        /// See http://tools.ietf.org/html/rfc6749#section-4.2.1 and
        /// http://openid.net/specs/openid-connect-core-1_0.html for more information.
        /// </summary>
        /// <param name="request">The <see cref="OpenIdConnectRequest"/> instance.</param>
        /// <returns><c>true</c> if the request is an hybrid flow request, <c>false</c> otherwise.</returns>
        public static bool IsHybridFlow([NotNull] this OpenIdConnectRequest request) {
            if (request == null) {
                throw new ArgumentNullException(nameof(request));
            }

            return SetEquals(request.ResponseType, OpenIdConnectConstants.ResponseTypes.Code,
                                                   OpenIdConnectConstants.ResponseTypes.IdToken) ||

                   SetEquals(request.ResponseType, OpenIdConnectConstants.ResponseTypes.Code,
                                                   OpenIdConnectConstants.ResponseTypes.Token) ||

                   SetEquals(request.ResponseType, OpenIdConnectConstants.ResponseTypes.Code,
                                                   OpenIdConnectConstants.ResponseTypes.IdToken,
                                                   OpenIdConnectConstants.ResponseTypes.Token);
        }

        /// <summary>
        /// Determines whether the "response_mode" parameter corresponds to the fragment response mode.
        /// See http://openid.net/specs/oauth-v2-multiple-response-types-1_0.html for more information.
        /// </summary>
        /// <param name="request">The <see cref="OpenIdConnectRequest"/> instance.</param>
        /// <returns>
        /// <c>true</c> if the request specified the fragment response mode or if
        /// it's the default value for the requested flow, <c>false</c> otherwise.
        /// </returns>
        public static bool IsFragmentResponseMode([NotNull] this OpenIdConnectRequest request) {
            if (request == null) {
                throw new ArgumentNullException(nameof(request));
            }

            if (string.Equals(request.ResponseMode, OpenIdConnectConstants.ResponseModes.Fragment, StringComparison.Ordinal)) {
                return true;
            }

            // Don't guess the response_mode value
            // if an explicit value has been provided.
            if (!string.IsNullOrEmpty(request.ResponseMode)) {
                return false;
            }

            // Both the implicit and the hybrid flows
            // use response_mode=fragment by default.
            return request.IsImplicitFlow() || request.IsHybridFlow();
        }

        /// <summary>
        /// Determines whether the "response_mode" parameter corresponds to the query response mode.
        /// See http://openid.net/specs/oauth-v2-multiple-response-types-1_0.html for more information.
        /// </summary>
        /// <param name="request">The <see cref="OpenIdConnectRequest"/> instance.</param>
        /// <returns>
        /// <c>true</c> if the request specified the query response mode or if
        /// it's the default value for the requested flow, <c>false</c> otherwise.
        /// </returns>
        public static bool IsQueryResponseMode([NotNull] this OpenIdConnectRequest request) {
            if (request == null) {
                throw new ArgumentNullException(nameof(request));
            }

            if (string.Equals(request.ResponseMode, OpenIdConnectConstants.ResponseModes.Query, StringComparison.Ordinal)) {
                return true;
            }

            // Don't guess the response_mode value
            // if an explicit value has been provided.
            if (!string.IsNullOrEmpty(request.ResponseMode)) {
                return false;
            }

            // Code flow and "response_type=none" use response_mode=query by default.
            return request.IsAuthorizationCodeFlow() || request.IsNoneFlow();
        }

        /// <summary>
        /// Determines whether the "response_mode" parameter corresponds to the form post response mode.
        /// See http://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html for more information.
        /// </summary>
        /// <param name="request">The <see cref="OpenIdConnectRequest"/> instance.</param>
        /// <returns>
        /// <c>true</c> if the request specified the form post response mode or if
        /// it's the default value for the requested flow, <c>false</c> otherwise.
        /// </returns>
        public static bool IsFormPostResponseMode([NotNull] this OpenIdConnectRequest request) {
            if (request == null) {
                throw new ArgumentNullException(nameof(request));
            }

            return string.Equals(request.ResponseMode, OpenIdConnectConstants.ResponseModes.FormPost, StringComparison.Ordinal);
        }

        /// <summary>
        /// Determines whether the "grant_type" parameter corresponds to the authorization code grant.
        /// See http://tools.ietf.org/html/rfc6749#section-4.1.3 for more information.
        /// </summary>
        /// <param name="request">The <see cref="OpenIdConnectRequest"/> instance.</param>
        /// <returns><c>true</c> if the request is a code grant request, <c>false</c> otherwise.</returns>
        public static bool IsAuthorizationCodeGrantType([NotNull] this OpenIdConnectRequest request) {
            if (request == null) {
                throw new ArgumentNullException(nameof(request));
            }

            return string.Equals(request.GrantType, OpenIdConnectConstants.GrantTypes.AuthorizationCode, StringComparison.Ordinal);
        }

        /// <summary>
        /// Determines whether the "grant_type" parameter corresponds to the client credentials grant.
        /// See http://tools.ietf.org/html/rfc6749#section-4.4.2 for more information.
        /// </summary>
        /// <param name="request">The <see cref="OpenIdConnectRequest"/> instance.</param>
        /// <returns><c>true</c> if the request is a client credentials grant request, <c>false</c> otherwise.</returns>
        public static bool IsClientCredentialsGrantType([NotNull] this OpenIdConnectRequest request) {
            if (request == null) {
                throw new ArgumentNullException(nameof(request));
            }

            return string.Equals(request.GrantType, OpenIdConnectConstants.GrantTypes.ClientCredentials, StringComparison.Ordinal);
        }

        /// <summary>
        /// Determines whether the "grant_type" parameter corresponds to the password grant.
        /// See http://tools.ietf.org/html/rfc6749#section-4.3.2 for more information.
        /// </summary>
        /// <param name="request">The <see cref="OpenIdConnectRequest"/> instance.</param>
        /// <returns><c>true</c> if the request is a password grant request, <c>false</c> otherwise.</returns>
        public static bool IsPasswordGrantType([NotNull] this OpenIdConnectRequest request) {
            if (request == null) {
                throw new ArgumentNullException(nameof(request));
            }

            return string.Equals(request.GrantType, OpenIdConnectConstants.GrantTypes.Password, StringComparison.Ordinal);
        }

        /// <summary>
        /// Determines whether the "grant_type" parameter corresponds to the refresh token grant.
        /// See http://tools.ietf.org/html/rfc6749#section-6 for more information.
        /// </summary>
        /// <param name="request">The <see cref="OpenIdConnectRequest"/> instance.</param>
        /// <returns><c>true</c> if the request is a refresh token grant request, <c>false</c> otherwise.</returns>
        public static bool IsRefreshTokenGrantType([NotNull] this OpenIdConnectRequest request) {
            if (request == null) {
                throw new ArgumentNullException(nameof(request));
            }

            return string.Equals(request.GrantType, OpenIdConnectConstants.GrantTypes.RefreshToken, StringComparison.Ordinal);
        }

        private static bool HasValue(string source, string value) {
            if (string.IsNullOrEmpty(source)) {
                return false;
            }

            return (from component in source.Split(OpenIdConnectConstants.Separators.Space, StringSplitOptions.RemoveEmptyEntries)
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
                collection: source.Split(OpenIdConnectConstants.Separators.Space, StringSplitOptions.RemoveEmptyEntries),
                comparer: StringComparer.Ordinal);

            return set.SetEquals(components);
        }
    }
}
