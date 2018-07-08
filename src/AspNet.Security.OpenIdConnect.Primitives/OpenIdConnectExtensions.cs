/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using JetBrains.Annotations;
using Microsoft.Extensions.Primitives;

namespace AspNet.Security.OpenIdConnect.Primitives
{
    /// <summary>
    /// Provides extension methods to make <see cref="OpenIdConnectRequest"/>
    /// and <see cref="OpenIdConnectResponse"/> easier to work with.
    /// </summary>
    public static class OpenIdConnectExtensions
    {
        /// <summary>
        /// Extracts the authentication context class values from an <see cref="OpenIdConnectRequest"/>.
        /// </summary>
        /// <param name="request">The <see cref="OpenIdConnectRequest"/> instance.</param>
        public static IEnumerable<string> GetAcrValues([NotNull] this OpenIdConnectRequest request)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            if (string.IsNullOrEmpty(request.AcrValues))
            {
                return Enumerable.Empty<string>();
            }

            return GetValues(request.AcrValues, OpenIdConnectConstants.Separators.Space).Distinct(StringComparer.Ordinal);
        }

        /// <summary>
        /// Extracts the scopes from an <see cref="OpenIdConnectRequest"/>.
        /// </summary>
        /// <param name="request">The <see cref="OpenIdConnectRequest"/> instance.</param>
        public static IEnumerable<string> GetScopes([NotNull] this OpenIdConnectRequest request)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            if (string.IsNullOrEmpty(request.Scope))
            {
                return Enumerable.Empty<string>();
            }

            return GetValues(request.Scope, OpenIdConnectConstants.Separators.Space).Distinct(StringComparer.Ordinal);
        }

        /// <summary>
        /// Determines whether the requested authentication context class values contain the specified item.
        /// </summary>
        /// <param name="request">The <see cref="OpenIdConnectRequest"/> instance.</param>
        /// <param name="value">The component to look for in the parameter.</param>
        public static bool HasAcrValue([NotNull] this OpenIdConnectRequest request, [NotNull] string value)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            if (string.IsNullOrEmpty(value))
            {
                throw new ArgumentException("The value cannot be null or empty.", nameof(value));
            }

            if (string.IsNullOrEmpty(request.AcrValues))
            {
                return false;
            }

            return HasValue(request.AcrValues, value, OpenIdConnectConstants.Separators.Space);
        }

        /// <summary>
        /// Determines whether the requested prompt contains the specified value.
        /// </summary>
        /// <param name="request">The <see cref="OpenIdConnectRequest"/> instance.</param>
        /// <param name="prompt">The component to look for in the parameter.</param>
        public static bool HasPrompt([NotNull] this OpenIdConnectRequest request, [NotNull] string prompt)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            if (string.IsNullOrEmpty(prompt))
            {
                throw new ArgumentException("The prompt cannot be null or empty.", nameof(prompt));
            }

            if (string.IsNullOrEmpty(request.Prompt))
            {
                return false;
            }

            return HasValue(request.Prompt, prompt, OpenIdConnectConstants.Separators.Space);
        }

        /// <summary>
        /// Determines whether the requested response type contains the specified value.
        /// </summary>
        /// <param name="request">The <see cref="OpenIdConnectRequest"/> instance.</param>
        /// <param name="type">The component to look for in the parameter.</param>
        public static bool HasResponseType([NotNull] this OpenIdConnectRequest request, [NotNull] string type)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            if (string.IsNullOrEmpty(type))
            {
                throw new ArgumentException("The response type cannot be null or empty.", nameof(type));
            }

            if (string.IsNullOrEmpty(request.ResponseType))
            {
                return false;
            }

            return HasValue(request.ResponseType, type, OpenIdConnectConstants.Separators.Space);
        }

        /// <summary>
        /// Determines whether the requested scope contains the specified value.
        /// </summary>
        /// <param name="request">The <see cref="OpenIdConnectRequest"/> instance.</param>
        /// <param name="scope">The component to look for in the parameter.</param>
        public static bool HasScope([NotNull] this OpenIdConnectRequest request, [NotNull] string scope)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            if (string.IsNullOrEmpty(scope))
            {
                throw new ArgumentException("The scope cannot be null or empty.", nameof(scope));
            }

            if (string.IsNullOrEmpty(request.Scope))
            {
                return false;
            }

            return HasValue(request.Scope, scope, OpenIdConnectConstants.Separators.Space);
        }

        /// <summary>
        /// Determines whether the given request is an authorization request.
        /// </summary>
        /// <param name="request">The <see cref="OpenIdConnectRequest"/> instance.</param>
        /// <returns><c>true</c> if the request is an authorization request, <c>false</c> otherwise.</returns>
        public static bool IsAuthorizationRequest([NotNull] this OpenIdConnectRequest request)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            var value = request.GetProperty<string>(OpenIdConnectConstants.Properties.MessageType);
            if (string.IsNullOrEmpty(value))
            {
                return false;
            }

            return string.Equals(value, OpenIdConnectConstants.MessageTypes.AuthorizationRequest, StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Determines whether the request was transmitted using a confidential channel
        /// (i.e if the transaction was only visible by the client and if client authentication was enforced).
        /// </summary>
        /// <param name="request">The <see cref="OpenIdConnectRequest"/> instance.</param>
        /// <returns><c>true</c> if the request is a configuration request, <c>false</c> otherwise.</returns>
        public static bool IsConfidential([NotNull] this OpenIdConnectRequest request)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            var value = request.GetProperty<string>(OpenIdConnectConstants.Properties.ConfidentialityLevel);
            if (string.IsNullOrEmpty(value))
            {
                return false;
            }

            return string.Equals(value, OpenIdConnectConstants.ConfidentialityLevels.Private, StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Determines whether the given request is a configuration request.
        /// </summary>
        /// <param name="request">The <see cref="OpenIdConnectRequest"/> instance.</param>
        /// <returns><c>true</c> if the request is a configuration request, <c>false</c> otherwise.</returns>
        public static bool IsConfigurationRequest([NotNull] this OpenIdConnectRequest request)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            var value = request.GetProperty<string>(OpenIdConnectConstants.Properties.MessageType);
            if (string.IsNullOrEmpty(value))
            {
                return false;
            }

            return string.Equals(value, OpenIdConnectConstants.MessageTypes.ConfigurationRequest, StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Determines whether the given request is a cryptography request.
        /// </summary>
        /// <param name="request">The <see cref="OpenIdConnectRequest"/> instance.</param>
        /// <returns><c>true</c> if the request is a cryptography request, <c>false</c> otherwise.</returns>
        public static bool IsCryptographyRequest([NotNull] this OpenIdConnectRequest request)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            var value = request.GetProperty<string>(OpenIdConnectConstants.Properties.MessageType);
            if (string.IsNullOrEmpty(value))
            {
                return false;
            }

            return string.Equals(value, OpenIdConnectConstants.MessageTypes.CryptographyRequest, StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Determines whether the given request is an introspection request.
        /// </summary>
        /// <param name="request">The <see cref="OpenIdConnectRequest"/> instance.</param>
        /// <returns><c>true</c> if the request is an introspection request, <c>false</c> otherwise.</returns>
        public static bool IsIntrospectionRequest([NotNull] this OpenIdConnectRequest request)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            var value = request.GetProperty<string>(OpenIdConnectConstants.Properties.MessageType);
            if (string.IsNullOrEmpty(value))
            {
                return false;
            }

            return string.Equals(value, OpenIdConnectConstants.MessageTypes.IntrospectionRequest, StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Determines whether the given request is a logout request.
        /// </summary>
        /// <param name="request">The <see cref="OpenIdConnectRequest"/> instance.</param>
        /// <returns><c>true</c> if the request is a logout request, <c>false</c> otherwise.</returns>
        public static bool IsLogoutRequest([NotNull] this OpenIdConnectRequest request)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            var value = request.GetProperty<string>(OpenIdConnectConstants.Properties.MessageType);
            if (string.IsNullOrEmpty(value))
            {
                return false;
            }

            return string.Equals(value, OpenIdConnectConstants.MessageTypes.LogoutRequest, StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Determines whether the given request is a revocation request.
        /// </summary>
        /// <param name="request">The <see cref="OpenIdConnectRequest"/> instance.</param>
        /// <returns><c>true</c> if the request is a revocation request, <c>false</c> otherwise.</returns>
        public static bool IsRevocationRequest([NotNull] this OpenIdConnectRequest request)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            var value = request.GetProperty<string>(OpenIdConnectConstants.Properties.MessageType);
            if (string.IsNullOrEmpty(value))
            {
                return false;
            }

            return string.Equals(value, OpenIdConnectConstants.MessageTypes.RevocationRequest, StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Determines whether the given request is a token request.
        /// </summary>
        /// <param name="request">The <see cref="OpenIdConnectRequest"/> instance.</param>
        /// <returns><c>true</c> if the request is a token request, <c>false</c> otherwise.</returns>
        public static bool IsTokenRequest([NotNull] this OpenIdConnectRequest request)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            var value = request.GetProperty<string>(OpenIdConnectConstants.Properties.MessageType);
            if (string.IsNullOrEmpty(value))
            {
                return false;
            }

            return string.Equals(value, OpenIdConnectConstants.MessageTypes.TokenRequest, StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Determines whether the given request is a userinfo request.
        /// </summary>
        /// <param name="request">The <see cref="OpenIdConnectRequest"/> instance.</param>
        /// <returns><c>true</c> if the request is a userinfo request, <c>false</c> otherwise.</returns>
        public static bool IsUserinfoRequest([NotNull] this OpenIdConnectRequest request)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            var value = request.GetProperty<string>(OpenIdConnectConstants.Properties.MessageType);
            if (string.IsNullOrEmpty(value))
            {
                return false;
            }

            return string.Equals(value, OpenIdConnectConstants.MessageTypes.UserinfoRequest, StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Determines whether the "response_type" parameter corresponds to the "none" response type.
        /// See http://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#none for more information.
        /// </summary>
        /// <param name="request">The <see cref="OpenIdConnectRequest"/> instance.</param>
        /// <returns><c>true</c> if the request is a response_type=none request, <c>false</c> otherwise.</returns>
        public static bool IsNoneFlow([NotNull] this OpenIdConnectRequest request)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            if (string.IsNullOrEmpty(request.ResponseType))
            {
                return false;
            }

            var segment = Trim(new StringSegment(request.ResponseType), OpenIdConnectConstants.Separators.Space);
            if (segment.Length == 0)
            {
                return false;
            }

            return segment.Equals(OpenIdConnectConstants.ResponseTypes.None, StringComparison.Ordinal);
        }

        /// <summary>
        /// Determines whether the "response_type" parameter corresponds to the authorization code flow.
        /// See http://tools.ietf.org/html/rfc6749#section-4.1.1 for more information.
        /// </summary>
        /// <param name="request">The <see cref="OpenIdConnectRequest"/> instance.</param>
        /// <returns><c>true</c> if the request is a code flow request, <c>false</c> otherwise.</returns>
        public static bool IsAuthorizationCodeFlow([NotNull] this OpenIdConnectRequest request)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            if (string.IsNullOrEmpty(request.ResponseType))
            {
                return false;
            }

            var segment = Trim(new StringSegment(request.ResponseType), OpenIdConnectConstants.Separators.Space);
            if (segment.Length == 0)
            {
                return false;
            }

            return segment.Equals(OpenIdConnectConstants.ResponseTypes.Code, StringComparison.Ordinal);
        }

        /// <summary>
        /// Determines whether the "response_type" parameter corresponds to the implicit flow.
        /// See http://tools.ietf.org/html/rfc6749#section-4.2.1 and
        /// http://openid.net/specs/openid-connect-core-1_0.html for more information
        /// </summary>
        /// <param name="request">The <see cref="OpenIdConnectRequest"/> instance.</param>
        /// <returns><c>true</c> if the request is an implicit flow request, <c>false</c> otherwise.</returns>
        public static bool IsImplicitFlow([NotNull] this OpenIdConnectRequest request)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            if (string.IsNullOrEmpty(request.ResponseType))
            {
                return false;
            }

            var flags = /* none: */ 0x00;

            foreach (var element in new StringTokenizer(request.ResponseType, OpenIdConnectConstants.Separators.Space))
            {
                var segment = Trim(element, OpenIdConnectConstants.Separators.Space);
                if (segment.Length == 0)
                {
                    continue;
                }

                if (segment.Equals(OpenIdConnectConstants.ResponseTypes.IdToken, StringComparison.Ordinal))
                {
                    flags |= /* id_token: */ 0x01;

                    continue;
                }

                // Note: though the OIDC core specs does not include the OAuth2-inherited response_type=token,
                // it is considered as a valid response_type for the implicit flow for backward compatibility.
                else if (segment.Equals(OpenIdConnectConstants.ResponseTypes.Token, StringComparison.Ordinal))
                {
                    flags |= /* token */ 0x02;

                    continue;
                }

                // Always return false if the response_type item
                // is not a valid component for the implicit flow.
                return false;
            }

            // Return true if the response_type parameter contains "id_token" or "token".
            return (flags & /* id_token: */ 0x01) == 0x01 || (flags & /* token: */ 0x02) == 0x02;
        }

        /// <summary>
        /// Determines whether the "response_type" parameter corresponds to the hybrid flow.
        /// See http://tools.ietf.org/html/rfc6749#section-4.2.1 and
        /// http://openid.net/specs/openid-connect-core-1_0.html for more information.
        /// </summary>
        /// <param name="request">The <see cref="OpenIdConnectRequest"/> instance.</param>
        /// <returns><c>true</c> if the request is an hybrid flow request, <c>false</c> otherwise.</returns>
        public static bool IsHybridFlow([NotNull] this OpenIdConnectRequest request)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            if (string.IsNullOrEmpty(request.ResponseType))
            {
                return false;
            }

            var flags = /* none */ 0x00;

            foreach (var element in new StringTokenizer(request.ResponseType, OpenIdConnectConstants.Separators.Space))
            {
                var segment = Trim(element, OpenIdConnectConstants.Separators.Space);
                if (segment.Length == 0)
                {
                    continue;
                }

                if (segment.Equals(OpenIdConnectConstants.ResponseTypes.Code, StringComparison.Ordinal))
                {
                    flags |= /* code: */ 0x01;

                    continue;
                }

                else if (segment.Equals(OpenIdConnectConstants.ResponseTypes.IdToken, StringComparison.Ordinal))
                {
                    flags |= /* id_token: */ 0x02;

                    continue;
                }

                else if (segment.Equals(OpenIdConnectConstants.ResponseTypes.Token, StringComparison.Ordinal))
                {
                    flags |= /* token: */ 0x04;

                    continue;
                }

                // Always return false if the response_type item
                // is not a valid component for the hybrid flow.
                return false;
            }

            // Return false if the response_type parameter doesn't contain "code".
            if ((flags & /* code: */ 0x01) != 0x01)
            {
                return false;
            }

            // Return true if the response_type parameter contains "id_token" or "token".
            return (flags & /* id_token: */ 0x02) == 0x02 || (flags & /* token: */ 0x04) == 0x04;
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
        public static bool IsFragmentResponseMode([NotNull] this OpenIdConnectRequest request)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            if (string.Equals(request.ResponseMode, OpenIdConnectConstants.ResponseModes.Fragment, StringComparison.Ordinal))
            {
                return true;
            }

            // Don't guess the response_mode value
            // if an explicit value has been provided.
            if (!string.IsNullOrEmpty(request.ResponseMode))
            {
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
        public static bool IsQueryResponseMode([NotNull] this OpenIdConnectRequest request)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            if (string.Equals(request.ResponseMode, OpenIdConnectConstants.ResponseModes.Query, StringComparison.Ordinal))
            {
                return true;
            }

            // Don't guess the response_mode value
            // if an explicit value has been provided.
            if (!string.IsNullOrEmpty(request.ResponseMode))
            {
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
        public static bool IsFormPostResponseMode([NotNull] this OpenIdConnectRequest request)
        {
            if (request == null)
            {
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
        public static bool IsAuthorizationCodeGrantType([NotNull] this OpenIdConnectRequest request)
        {
            if (request == null)
            {
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
        public static bool IsClientCredentialsGrantType([NotNull] this OpenIdConnectRequest request)
        {
            if (request == null)
            {
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
        public static bool IsPasswordGrantType([NotNull] this OpenIdConnectRequest request)
        {
            if (request == null)
            {
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
        public static bool IsRefreshTokenGrantType([NotNull] this OpenIdConnectRequest request)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            return string.Equals(request.GrantType, OpenIdConnectConstants.GrantTypes.RefreshToken, StringComparison.Ordinal);
        }

        private static IEnumerable<string> GetValues(string source, char[] separators)
        {
            Debug.Assert(!string.IsNullOrEmpty(source), "The source string shouldn't be null or empty.");
            Debug.Assert(separators?.Length != 0, "The separators collection shouldn't be null or empty.");

            foreach (var element in new StringTokenizer(source, separators))
            {
                var segment = Trim(element, separators);
                if (segment.Length == 0)
                {
                    continue;
                }

                yield return segment.Value;
            }

            yield break;
        }

        private static bool HasValue(string source, string value, char[] separators)
        {
            Debug.Assert(!string.IsNullOrEmpty(source), "The source string shouldn't be null or empty.");
            Debug.Assert(!string.IsNullOrEmpty(value), "The value string shouldn't be null or empty.");
            Debug.Assert(separators?.Length != 0, "The separators collection shouldn't be null or empty.");

            foreach (var element in new StringTokenizer(source, separators))
            {
                var segment = Trim(element, separators);
                if (segment.Length == 0)
                {
                    continue;
                }

                if (segment.Equals(value, StringComparison.Ordinal))
                {
                    return true;
                }
            }

            return false;
        }

        private static StringSegment TrimStart(StringSegment segment, char[] separators)
        {
            Debug.Assert(separators?.Length != 0, "The separators collection shouldn't be null or empty.");

            var index = segment.Offset;

            while (index < segment.Offset + segment.Length)
            {
                if (!IsSeparator(segment.Buffer[index], separators))
                {
                    break;
                }

                index++;
            }

            return new StringSegment(segment.Buffer, index, segment.Offset + segment.Length - index);
        }

        private static StringSegment TrimEnd(StringSegment segment, char[] separators)
        {
            Debug.Assert(separators?.Length != 0, "The separators collection shouldn't be null or empty.");

            var index = segment.Offset + segment.Length - 1;

            while (index >= segment.Offset)
            {
                if (!IsSeparator(segment.Buffer[index], separators))
                {
                    break;
                }

                index--;
            }

            return new StringSegment(segment.Buffer, segment.Offset, index - segment.Offset + 1);
        }

        private static StringSegment Trim(StringSegment segment, char[] separators)
        {
            Debug.Assert(separators?.Length != 0, "The separators collection shouldn't be null or empty.");

            return TrimEnd(TrimStart(segment, separators), separators);
        }

        private static bool IsSeparator(char character, char[] separators)
        {
            Debug.Assert(separators?.Length != 0, "The separators collection shouldn't be null or empty.");

            for (var index = 0; index < separators.Length; index++)
            {
                if (character == separators[index])
                {
                    return true;
                }
            }

            return false;
        }
    }
}
