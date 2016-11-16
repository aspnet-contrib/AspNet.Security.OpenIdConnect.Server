using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using JetBrains.Annotations;
using Microsoft.Extensions.Primitives;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace AspNet.Security.OpenIdConnect.Extensions {
    /// <summary>
    /// Represents a generic OpenID Connect request.
    /// </summary>
    [DebuggerDisplay("Parameters: {Parameters.Count}"), JsonDictionary]
    public class OpenIdConnectRequest : IDictionary<string, JToken> {
        /// <summary>
        /// Initializes a new OpenID Connect request.
        /// </summary>
        public OpenIdConnectRequest() { }

        /// <summary>
        /// Initializes a new OpenID Connect request.
        /// </summary>
        /// <param name="payload">The request payload.</param>
        public OpenIdConnectRequest([NotNull] JObject payload) {
            if (payload == null) {
                throw new ArgumentNullException(nameof(payload));
            }

            foreach (var parameter in payload.Properties()) {
                SetParameter(parameter.Name, parameter.Value);
            }
        }

        /// <summary>
        /// Initializes a new OpenID Connect request.
        /// </summary>
        /// <param name="parameters">The request parameters.</param>
        public OpenIdConnectRequest([NotNull] IDictionary<string, string> parameters) {
            if (parameters == null) {
                throw new ArgumentNullException(nameof(parameters));
            }

            foreach (var parameter in parameters) {
                SetParameter(parameter.Key, parameter.Value);
            }
        }

        /// <summary>
        /// Initializes a new OpenID Connect request.
        /// </summary>
        /// <param name="parameters">The request parameters.</param>
        public OpenIdConnectRequest([NotNull] IDictionary<string, JToken> parameters) {
            if (parameters == null) {
                throw new ArgumentNullException(nameof(parameters));
            }

            foreach (var parameter in parameters) {
                SetParameter(parameter.Key, parameter.Value);
            }
        }

        /// <summary>
        /// Initializes a new OpenID Connect request.
        /// </summary>
        /// <param name="parameters">The request parameters.</param>
        public OpenIdConnectRequest([NotNull] IEnumerable<KeyValuePair<string, StringValues>> parameters) {
            if (parameters == null) {
                throw new ArgumentNullException(nameof(parameters));
            }

            foreach (var parameter in parameters) {
                SetParameter(parameter.Key, (string) parameter.Value);
            }
        }

        /// <summary>
        /// Gets or sets the "access_token" parameter.
        /// </summary>
        public string AccessToken {
            get { return GetParameter<string>(OpenIdConnectConstants.Parameters.AccessToken); }
            set { SetParameter(OpenIdConnectConstants.Parameters.AccessToken, value); }
        }

        /// <summary>
        /// Gets or sets the "assertion" parameter.
        /// </summary>
        public string Assertion {
            get { return GetParameter<string>(OpenIdConnectConstants.Parameters.Assertion); }
            set { SetParameter(OpenIdConnectConstants.Parameters.Assertion, value); }
        }

        /// <summary>
        /// Gets or sets the "client_assertion" parameter.
        /// </summary>
        public string ClientAssertion {
            get { return GetParameter<string>(OpenIdConnectConstants.Parameters.ClientAssertion); }
            set { SetParameter(OpenIdConnectConstants.Parameters.ClientAssertion, value); }
        }

        /// <summary>
        /// Gets or sets the "client_assertion_type" parameter.
        /// </summary>
        public string ClientAssertionType {
            get { return GetParameter<string>(OpenIdConnectConstants.Parameters.ClientAssertionType); }
            set { SetParameter(OpenIdConnectConstants.Parameters.ClientAssertionType, value); }
        }

        /// <summary>
        /// Gets or sets the "client_id" parameter.
        /// </summary>
        public string ClientId {
            get { return GetParameter<string>(OpenIdConnectConstants.Parameters.ClientId); }
            set { SetParameter(OpenIdConnectConstants.Parameters.ClientId, value); }
        }

        /// <summary>
        /// Gets or sets the "client_secret" parameter.
        /// </summary>
        public string ClientSecret {
            get { return GetParameter<string>(OpenIdConnectConstants.Parameters.ClientSecret); }
            set { SetParameter(OpenIdConnectConstants.Parameters.ClientSecret, value); }
        }

        /// <summary>
        /// Gets or sets the "code" parameter.
        /// </summary>
        public string Code {
            get { return GetParameter<string>(OpenIdConnectConstants.Parameters.Code); }
            set { SetParameter(OpenIdConnectConstants.Parameters.Code, value); }
        }

        /// <summary>
        /// Gets or sets the "code_challenge" parameter.
        /// </summary>
        public string CodeChallenge {
            get { return GetParameter<string>(OpenIdConnectConstants.Parameters.CodeChallenge); }
            set { SetParameter(OpenIdConnectConstants.Parameters.CodeChallenge, value); }
        }

        /// <summary>
        /// Gets or sets the "code_challenge_method" parameter.
        /// </summary>
        public string CodeChallengeMethod {
            get { return GetParameter<string>(OpenIdConnectConstants.Parameters.CodeChallengeMethod); }
            set { SetParameter(OpenIdConnectConstants.Parameters.CodeChallengeMethod, value); }
        }

        /// <summary>
        /// Gets or sets the "code_verifier" parameter.
        /// </summary>
        public string CodeVerifier {
            get { return GetParameter<string>(OpenIdConnectConstants.Parameters.CodeVerifier); }
            set { SetParameter(OpenIdConnectConstants.Parameters.CodeVerifier, value); }
        }

        /// <summary>
        /// Gets or sets the "grant_type" parameter.
        /// </summary>
        public string GrantType {
            get { return GetParameter<string>(OpenIdConnectConstants.Parameters.GrantType); }
            set { SetParameter(OpenIdConnectConstants.Parameters.GrantType, value); }
        }

        /// <summary>
        /// Gets or sets the "id_token_hint" parameter.
        /// </summary>
        public string IdTokenHint {
            get { return GetParameter<string>(OpenIdConnectConstants.Parameters.IdTokenHint); }
            set { SetParameter(OpenIdConnectConstants.Parameters.IdTokenHint, value); }
        }

        /// <summary>
        /// Gets or sets the "nonce" parameter.
        /// </summary>
        public string Nonce {
            get { return GetParameter<string>(OpenIdConnectConstants.Parameters.Nonce); }
            set { SetParameter(OpenIdConnectConstants.Parameters.Nonce, value); }
        }

        /// <summary>
        /// Gets or sets the "password" parameter.
        /// </summary>
        public string Password {
            get { return GetParameter<string>(OpenIdConnectConstants.Parameters.Password); }
            set { SetParameter(OpenIdConnectConstants.Parameters.Password, value); }
        }

        /// <summary>
        /// Gets or sets the "post_logout_redirect_uri" parameter.
        /// </summary>
        public string PostLogoutRedirectUri {
            get { return GetParameter<string>(OpenIdConnectConstants.Parameters.PostLogoutRedirectUri); }
            set { SetParameter(OpenIdConnectConstants.Parameters.PostLogoutRedirectUri, value); }
        }

        /// <summary>
        /// Gets or sets the "prompt" parameter.
        /// </summary>
        public string Prompt {
            get { return GetParameter<string>(OpenIdConnectConstants.Parameters.Prompt); }
            set { SetParameter(OpenIdConnectConstants.Parameters.Prompt, value); }
        }

        /// <summary>
        /// Gets or sets the "redirect_uri" parameter.
        /// </summary>
        public string RedirectUri {
            get { return GetParameter<string>(OpenIdConnectConstants.Parameters.RedirectUri); }
            set { SetParameter(OpenIdConnectConstants.Parameters.RedirectUri, value); }
        }

        /// <summary>
        /// Gets or sets the "refresh_token" parameter.
        /// </summary>
        public string RefreshToken {
            get { return GetParameter<string>(OpenIdConnectConstants.Parameters.RefreshToken); }
            set { SetParameter(OpenIdConnectConstants.Parameters.RefreshToken, value); }
        }

        /// <summary>
        /// Gets or sets the "request" parameter.
        /// </summary>
        public string Request {
            get { return GetParameter<string>(OpenIdConnectConstants.Parameters.Request); }
            set { SetParameter(OpenIdConnectConstants.Parameters.Request, value); }
        }

        /// <summary>
        /// Gets or sets the "request_id" parameter.
        /// </summary>
        public string RequestId {
            get { return GetParameter<string>(OpenIdConnectConstants.Parameters.RequestId); }
            set { SetParameter(OpenIdConnectConstants.Parameters.RequestId, value); }
        }

        /// <summary>
        /// Gets or sets the "request_uri" parameter.
        /// </summary>
        public string RequestUri {
            get { return GetParameter<string>(OpenIdConnectConstants.Parameters.RequestUri); }
            set { SetParameter(OpenIdConnectConstants.Parameters.RequestUri, value); }
        }

        /// <summary>
        /// Gets or sets the "resource" parameter.
        /// </summary>
        public string Resource {
            get { return GetParameter<string>(OpenIdConnectConstants.Parameters.Resource); }
            set { SetParameter(OpenIdConnectConstants.Parameters.Resource, value); }
        }

        /// <summary>
        /// Gets or sets the "response_mode" parameter.
        /// </summary>
        public string ResponseMode {
            get { return GetParameter<string>(OpenIdConnectConstants.Parameters.ResponseMode); }
            set { SetParameter(OpenIdConnectConstants.Parameters.ResponseMode, value); }
        }

        /// <summary>
        /// Gets or sets the "response_type" parameter.
        /// </summary>
        public string ResponseType {
            get { return GetParameter<string>(OpenIdConnectConstants.Parameters.ResponseType); }
            set { SetParameter(OpenIdConnectConstants.Parameters.ResponseType, value); }
        }

        /// <summary>
        /// Gets or sets the "scope" parameter.
        /// </summary>
        public string Scope {
            get { return GetParameter<string>(OpenIdConnectConstants.Parameters.Scope); }
            set { SetParameter(OpenIdConnectConstants.Parameters.Scope, value); }
        }

        /// <summary>
        /// Gets or sets the "state" parameter.
        /// </summary>
        public string State {
            get { return GetParameter<string>(OpenIdConnectConstants.Parameters.State); }
            set { SetParameter(OpenIdConnectConstants.Parameters.State, value); }
        }

        /// <summary>
        /// Gets or sets the "token" parameter.
        /// </summary>
        public string Token {
            get { return GetParameter<string>(OpenIdConnectConstants.Parameters.Token); }
            set { SetParameter(OpenIdConnectConstants.Parameters.Token, value); }
        }

        /// <summary>
        /// Gets or sets the "token_type_hint" parameter.
        /// </summary>
        public string TokenTypeHint {
            get { return GetParameter<string>(OpenIdConnectConstants.Parameters.TokenTypeHint); }
            set { SetParameter(OpenIdConnectConstants.Parameters.TokenTypeHint, value); }
        }

        /// <summary>
        /// Gets or sets the "username" parameter.
        /// </summary>
        public string Username {
            get { return GetParameter<string>(OpenIdConnectConstants.Parameters.Username); }
            set { SetParameter(OpenIdConnectConstants.Parameters.Username, value); }
        }

        /// <summary>
        /// Gets or sets an OpenID Connect request parameter.
        /// </summary>
        /// <param name="name">The parameter name.</param>
        /// <returns>The parameter value.</returns>
        public JToken this[string name] {
            get { return GetParameter(name); }
            set { SetParameter(name, value); }
        }

        /// <summary>
        /// Gets the dictionary containing the OpenID Connect request parameters.
        /// </summary>
        protected internal virtual Dictionary<string, JToken> Parameters { get; } =
            new Dictionary<string, JToken>(StringComparer.Ordinal);

        /// <summary>
        /// Gets the dictionary containing the properties associated with this OpenID Connect request.
        /// Note: these properties are not meant to be publicly shared and shouldn't be serialized.
        /// </summary>
        protected internal virtual Dictionary<string, string> Properties { get; } =
            new Dictionary<string, string>(StringComparer.Ordinal);

        /// <summary>
        /// Gets an enumerator allowing to iterate the parameter details.
        /// </summary>
        /// <returns>An enumerator.</returns>
        public IEnumerator<KeyValuePair<string, JToken>> GetEnumerator() {
            return Parameters.GetEnumerator();
        }

        /// <summary>
        /// Gets the value corresponding to a given OpenID Connect request parameter.
        /// </summary>
        /// <param name="name">The parameter value.</param>
        /// <returns>The parameter value, or <c>null</c> if it cannot be found.</returns>
        public virtual JToken GetParameter([NotNull] string name) {
            if (string.IsNullOrEmpty(name)) {
                throw new ArgumentException("The parameter name cannot be null or empty.", nameof(name));
            }

            JToken value;
            if (Parameters.TryGetValue(name, out value)) {
                return value;
            }

            return null;
        }

        /// <summary>
        /// Gets the value corresponding to a given OpenID Connect request parameter.
        /// </summary>
        /// <param name="name">The parameter name.</param>
        /// <returns>The parameter value, or the default value for the
        /// <typeparamref name="T"/> type if it cannot be found.</returns>
        public virtual T GetParameter<T>([NotNull] string name) {
            if (string.IsNullOrEmpty(name)) {
                throw new ArgumentException("The parameter name cannot be null or empty.", nameof(name));
            }

            var parameter = GetParameter(name);
            if (parameter == null) {
                return default(T);
            }

            if (typeof(T) == typeof(string)) {
                var value = parameter as JValue;
                if (value == null) {
                    return default(T);
                }

                return (T) (object) (string) value;
            }

            return parameter.ToObject<T>();
        }

        /// <summary>
        /// Gets the value corresponding to a given property associated with this request.
        /// </summary>
        /// <param name="name">The property name.</param>
        /// <returns>The property value, or <c>null</c> if it cannot be found.</returns>
        public virtual string GetProperty([NotNull] string name) {
            if (string.IsNullOrEmpty(name)) {
                throw new ArgumentException("The property name cannot be null or empty.", nameof(name));
            }

            string property;
            if (Properties.TryGetValue(name, out property)) {
                return property;
            }

            return null;
        }

        /// <summary>
        /// Adds, replaces or removes an OpenID Connect request parameter.
        /// </summary>
        /// <param name="name">The parameter name.</param>
        /// <param name="value">The parameter value.</param>
        /// <returns>The current OpenID Connect request.</returns>
        public virtual OpenIdConnectRequest SetParameter([NotNull] string name, JToken value) {
            if (string.IsNullOrEmpty(name)) {
                throw new ArgumentException("The parameter name cannot be null or empty.", nameof(name));
            }

            // If the parameter value is null, remove the corresponding entry in the collection.
            if (value == null || (value.Type == JTokenType.Array && !value.HasValues) ||
                                 (value.Type == JTokenType.Object && !value.HasValues) ||
                                 (value.Type == JTokenType.String && string.IsNullOrEmpty((string) value)) ||
                                 (value.Type == JTokenType.Null)) {
                Parameters.Remove(name);

                return this;
            }

            Parameters[name] = value;

            return this;
        }

        /// <summary>
        /// Adds, replaces or removes a property.
        /// </summary>
        /// <param name="name">The property name.</param>
        /// <param name="value">The property value.</param>
        /// <returns>The current OpenID Connect request.</returns>
        public virtual OpenIdConnectRequest SetProperty([NotNull] string name, string value) {
            if (string.IsNullOrEmpty(name)) {
                throw new ArgumentException("The property name cannot be null or empty.", nameof(name));
            }

            // If the property value is null, remove the corresponding entry in the collection.
            if (value == null) {
                Properties.Remove(name);

                return this;
            }

            Properties[name] = value;

            return this;
        }

        /// <summary>
        /// Gets the parameter names contained in this request.
        /// </summary>
        ICollection<string> IDictionary<string, JToken>.Keys => Parameters.Keys;

        /// <summary>
        /// Gets the parameter values contained in this request.
        /// </summary>
        ICollection<JToken> IDictionary<string, JToken>.Values => Parameters.Values;

        /// <summary>
        /// Gets a parameter corresponding to the given name.
        /// </summary>
        /// <param name="key">The parameter name.</param>
        /// <returns>The value associated with the parameter.</returns>
        JToken IDictionary<string, JToken>.this[string key] {
            get { return this[key]; }
            set { this[key] = value; }
        }

        /// <summary>
        /// Gets a boolean indicating whether a parameter exists in the current request.
        /// </summary>
        /// <param name="key">The parameter name.</param>
        /// <returns><c>true</c> if the parameter exists, <c>false</c> otherwise.</returns>
        bool IDictionary<string, JToken>.ContainsKey(string key) => Parameters.ContainsKey(key);

        /// <summary>
        /// Adds a new parameter in the current request.
        /// </summary>
        /// <param name="key">The parameter name.</param>
        /// <param name="value">The parameter value.</param>
        void IDictionary<string, JToken>.Add(string key, JToken value) => SetParameter(key, value);

        /// <summary>
        /// Removes a parameter from the current request.
        /// </summary>
        /// <param name="key">The parameter name.</param>
        /// <returns><c>true</c> if the parameter was removed, <c>false</c> otherwise.</returns>
        bool IDictionary<string, JToken>.Remove(string key) => Parameters.Remove(key);

        /// <summary>
        /// Gets the value corresponding to the specified parameter.
        /// </summary>
        /// <param name="key">The parameter name.</param>
        /// <param name="value">The parameter value.</param>
        /// <returns><c>true</c> if the parameter was successfully retrieved, <c>false</c> otherwise.</returns>
        bool IDictionary<string, JToken>.TryGetValue(string key, out JToken value) {
            return Parameters.TryGetValue(key, out value);
        }

        /// <summary>
        /// Gets the number of parameters contained in this request.
        /// </summary>
        int ICollection<KeyValuePair<string, JToken>>.Count => Parameters.Count;

        /// <summary>
        /// Gets a boolean indicating whether this request is read-only.
        /// </summary>
        bool ICollection<KeyValuePair<string, JToken>>.IsReadOnly => false;

        /// <summary>
        /// Adds a new parameter in the current request.
        /// </summary>
        /// <param name="item">The parameter details.</param>
        void ICollection<KeyValuePair<string, JToken>>.Add(KeyValuePair<string, JToken> item) {
            SetParameter(item.Key, item.Value);
        }

        /// <summary>
        /// Clears the parameters contained in this request.
        /// </summary>
        void ICollection<KeyValuePair<string, JToken>>.Clear() => Parameters.Clear();

        /// <summary>
        /// Gets a boolean indicating whether a parameter exists in the current request.
        /// </summary>
        /// <param name="item">The parameter details.</param>
        /// <returns><c>true</c> if the parameter exists, <c>false</c> otherwise.</returns>
        bool ICollection<KeyValuePair<string, JToken>>.Contains(KeyValuePair<string, JToken> item) {
            return (Parameters as ICollection<KeyValuePair<string, JToken>>).Contains(item);
        }

        /// <summary>
        /// Copies the current request paramaters to a given array.
        /// </summary>
        /// <param name="array">The array the parameters are copied to.</param>
        /// <param name="index">The zero-based index in array at which copying begins.</param>
        void ICollection<KeyValuePair<string, JToken>>.CopyTo(KeyValuePair<string, JToken>[] array, int index) {
            (Parameters as ICollection<KeyValuePair<string, JToken>>).CopyTo(array, index);
        }

        /// <summary>
        /// Removes a parameter from the current request.
        /// </summary>
        /// <param name="item">The parameter details.</param>
        /// <returns><c>true</c> if the parameter was removed, <c>false</c> otherwise.</returns>
        bool ICollection<KeyValuePair<string, JToken>>.Remove(KeyValuePair<string, JToken> item) {
            return (Parameters as ICollection<KeyValuePair<string, JToken>>).Remove(item);
        }

        /// <summary>
        /// Gets an enumerator allowing to iterate the parameter details.
        /// </summary>
        /// <returns>An enumerator.</returns>
        IEnumerator IEnumerable.GetEnumerator() => Parameters.GetEnumerator();
    }
}
