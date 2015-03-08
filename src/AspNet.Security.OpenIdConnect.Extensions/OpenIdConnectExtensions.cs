using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.IdentityModel.Protocols;

namespace AspNet.Security.OpenIdConnect.Extensions {
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
                throw new ArgumentNullException(nameof(message));
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
                throw new ArgumentNullException(nameof(message));
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
                throw new ArgumentNullException(nameof(message));
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
                throw new ArgumentNullException(nameof(message));
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
                throw new ArgumentNullException(nameof(message));
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
                throw new ArgumentNullException(nameof(message));
            }

            return string.Equals(message.ResponseMode, OpenIdConnectConstants.ResponseModes.FormPost, StringComparison.Ordinal);
        }

        /// <summary>
        /// True when the "grant_type" is "authorization_code".
        /// See also http://tools.ietf.org/html/rfc6749#section-4.1.3
        /// </summary>    
        public static bool IsAuthorizationCodeGrantType(this OpenIdConnectMessage message) {
            if (message == null) {
                throw new ArgumentNullException(nameof(message));
            }

            return string.Equals(message.GrantType, OpenIdConnectConstants.GrantTypes.AuthorizationCode, StringComparison.Ordinal);
        }

        /// <summary>
        /// True when the "grant_type" is "client_credentials".
        /// See also http://tools.ietf.org/html/rfc6749#section-4.4.2
        /// </summary>  
        public static bool IsClientCredentialsGrantType(this OpenIdConnectMessage message) {
            if (message == null) {
                throw new ArgumentNullException(nameof(message));
            }

            return string.Equals(message.GrantType, OpenIdConnectConstants.GrantTypes.ClientCredentials, StringComparison.Ordinal);
        }

        /// <summary>
        /// True when the "grant_type" is "refresh_token".
        /// See also http://tools.ietf.org/html/rfc6749#section-6
        /// </summary>    
        public static bool IsRefreshTokenGrantType(this OpenIdConnectMessage message) {
            if (message == null) {
                throw new ArgumentNullException(nameof(message));
            }

            return string.Equals(message.GrantType, OpenIdConnectConstants.GrantTypes.RefreshToken, StringComparison.Ordinal);
        }

        /// <summary>
        /// True when the "grant_type" is "password".
        /// See also http://tools.ietf.org/html/rfc6749#section-4.3.2
        /// </summary>    
        public static bool IsPasswordGrantType(this OpenIdConnectMessage message) {
            if (message == null) {
                throw new ArgumentNullException(nameof(message));
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
                throw new ArgumentNullException(nameof(message));
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
                throw new ArgumentNullException(nameof(message));
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
                throw new ArgumentNullException(nameof(message));
            }

            if (parameter == null) {
                throw new ArgumentNullException(nameof(parameter));
            }

            return HasValue(source: parameter(message), value: component);
        }

        private static bool HasValue(string source, string value) {
            if (string.IsNullOrWhiteSpace(source)) {
                return false;
            }

            return (from component in source.Split(' ')
                    where string.Equals(component, value, StringComparison.Ordinal)
                    select component).Any();
        }

        private static bool SetEquals(string source, params string[] components) {
            if (string.IsNullOrWhiteSpace(source)) {
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
