/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/AspNet-OpenIdConnect-Server/Owin.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using Microsoft.Owin;

namespace Owin.Security.OpenIdConnect.Server.Messages {
    /// <summary>
    /// Data object representing the information contained in the query string of an authorization request.
    /// </summary>
    public class OpenIdConnectAuthorizationRequest {
        /// <summary>
        /// Creates a new instance populated with parameters extracted from the ambient request.
        /// </summary>
        /// <param name="parameters">Parameters extracted from the ambient request.</param>
        public OpenIdConnectAuthorizationRequest(IReadableStringCollection parameters) {
            if (parameters == null) {
                throw new ArgumentNullException("parameters");
            }

            Parameters = parameters;
            Scope = new List<string>();

            foreach (var parameter in parameters) {
                AddParameter(parameter.Key, parameters.Get(parameter.Key));
            }
        }

        /// <summary>
        /// The "response_type" parameter of the authorization request. Known values are "code" and "token".
        /// </summary>
        public string ResponseType { get; set; }

        /// <summary>
        /// The "response_mode" parameter of the authorization request. Known values are "query", "fragment" and "form_post"
        /// See also, http://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html
        /// </summary>
        public string ResponseMode { get; set; }

        /// <summary>
        /// The "client_id" parameter of the authorization request. 
        /// </summary>
        public string ClientId { get; set; }

        /// <summary>
        /// The parameters collection used to build the current request.
        /// </summary>
        public IReadableStringCollection Parameters { get; private set; }

        /// <summary>
        /// The "redirect_uri" parameter of the authorization request.
        /// May be absent if the server should use the 
        /// redirect uri known to be registered to the client id.
        /// </summary>
        [SuppressMessage("Microsoft.Design",
            "CA1056:UriPropertiesShouldNotBeStrings",
            Justification = "By design")]
        public string RedirectUri { get; set; }

        /// <summary>
        /// The "scope" parameter of the authorization request.
        /// May be absent if the server should use default scopes.
        /// </summary>
        public IList<string> Scope { get; private set; }

        /// <summary>
        /// The "nonce" parameter of the authorization request.
        /// </summary>
        public string Nonce { get; set; }

        /// <summary>
        /// The "scope" parameter of the authorization request.
        /// May be absent if the client does not require state to be 
        /// included when returning to the RedirectUri.
        /// </summary>
        public string State { get; set; }

        /// <summary>
        /// True if the "response_type" parameter is "code".
        /// See http://tools.ietf.org/html/rfc6749#section-4.1.1
        /// </summary>
        public bool IsAuthorizationCodeFlow {
            get { return string.Equals(ResponseType, OpenIdConnectConstants.ResponseTypes.Code); }
        }

        /// <summary>
        /// True if the "response_type" parameter
        /// contains "token" and/or "id_token" but not "code".
        /// See http://tools.ietf.org/html/rfc6749#section-4.2.1 and
        /// http://openid.net/specs/openid-connect-core-1_0.html
        /// </summary>
        public bool IsImplicitFlow {
            get {
                // Note: while the OIDC specs do not reuse the OAuth2-inherited response_type=token,
                // it is considered as a valid response_type for the implicit flow, even for pure OIDC requests.
                return !ContainsResponseType(OpenIdConnectConstants.ResponseTypes.Code) &&
                    (ContainsResponseType(OpenIdConnectConstants.ResponseTypes.IdToken) ||
                     ContainsResponseType(OpenIdConnectConstants.ResponseTypes.Token));
            }
        }

        /// <summary>
        /// True if the "response_type" parameter
        /// contains "code" and "token" and/or "id_token".
        /// See http://tools.ietf.org/html/rfc6749#section-4.2.1 and
        /// http://openid.net/specs/openid-connect-core-1_0.html
        /// </summary>
        public bool IsHybridFlow {
            get {
                return ContainsResponseType(OpenIdConnectConstants.ResponseTypes.Code) &&
                    (ContainsResponseType(OpenIdConnectConstants.ResponseTypes.IdToken) ||
                     ContainsResponseType(OpenIdConnectConstants.ResponseTypes.Token));
            }
        }

        /// <summary>
        /// True if the "response_mode" parameter is "fragment".
        /// See http://openid.net/specs/oauth-v2-multiple-response-types-1_0.html
        /// </summary>
        public bool IsFragmentResponseMode {
            get { return string.Equals(ResponseMode, OpenIdConnectConstants.ResponseModes.Fragment, StringComparison.Ordinal); }
        }

        /// <summary>
        /// True if the "response_mode" parameter is "query".
        /// See http://openid.net/specs/oauth-v2-multiple-response-types-1_0.html
        /// </summary>
        public bool IsQueryResponseMode {
            get { return string.Equals(ResponseMode, OpenIdConnectConstants.ResponseModes.Query, StringComparison.Ordinal); }
        }

        /// <summary>
        /// True if the "response_mode" parameter is "form_post".
        /// See http://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html
        /// </summary>
        public bool IsFormPostResponseMode {
            get { return string.Equals(ResponseMode, OpenIdConnectConstants.ResponseModes.FormPost, StringComparison.Ordinal); }
        }

        /// <summary>
        /// True if the "response_type" parameter contains the given responseType.
        /// See also, http://openid.net/specs/oauth-v2-multiple-response-types-1_0.html
        /// </summary>
        /// <param name="responseType">The responseType to look for within the "response_type" parameter.</param>
        /// <returns>True if the "response_type" query string contains the given responseType.</returns>
        public bool ContainsResponseType(string responseType) {
            foreach (var part in ResponseType.Split(' ')) {
                if (string.Equals(part, responseType, StringComparison.Ordinal)) {
                    return true;
                }
            }

            return false;
        }

        private void AddParameter(string name, string value) {
            if (string.Equals(name, OpenIdConnectConstants.Parameters.ResponseType, StringComparison.Ordinal)) {
                ResponseType = value;
            }

            else if (string.Equals(name, OpenIdConnectConstants.Parameters.ClientId, StringComparison.Ordinal)) {
                ClientId = value;
            }

            else if (string.Equals(name, OpenIdConnectConstants.Parameters.RedirectUri, StringComparison.Ordinal)) {
                RedirectUri = value;
            }

            else if (string.Equals(name, OpenIdConnectConstants.Parameters.Scope, StringComparison.Ordinal)) {
                Scope = value.Split(' ');
            }

            else if (string.Equals(name, OpenIdConnectConstants.Parameters.Nonce, StringComparison.Ordinal)) {
                Nonce = value;
            }

            else if (string.Equals(name, OpenIdConnectConstants.Parameters.State, StringComparison.Ordinal)) {
                State = value;
            }

            else if (string.Equals(name, OpenIdConnectConstants.Parameters.ResponseMode, StringComparison.Ordinal)) {
                ResponseMode = value;
            }
        }
    }
}
