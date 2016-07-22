using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using JetBrains.Annotations;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace Owin.Security.OpenIdConnect.Extensions {
    /// <summary>
    /// Represents a generic OpenID Connect response.
    /// </summary>
    [DebuggerDisplay("Parameters: {Parameters.Count}"), JsonDictionary]
    public class OpenIdConnectResponse : IDictionary<string, JToken> {
        /// <summary>
        /// Initializes a new OpenID Connect response.
        /// </summary>
        public OpenIdConnectResponse() { }

        /// <summary>
        /// Initializes a new OpenID Connect response.
        /// </summary>
        /// <param name="payload">The response payload.</param>
        public OpenIdConnectResponse([NotNull] JObject payload) {
            if (payload == null) {
                throw new ArgumentNullException(nameof(payload));
            }

            foreach (var parameter in payload.Properties()) {
                SetParameter(parameter.Name, parameter);
            }
        }

        /// <summary>
        /// Initializes a new OpenID Connect response.
        /// </summary>
        /// <param name="parameters">The response parameters.</param>
        public OpenIdConnectResponse([NotNull] IDictionary<string, string> parameters) {
            if (parameters == null) {
                throw new ArgumentNullException(nameof(parameters));
            }

            foreach (var parameter in parameters) {
                SetParameter(parameter.Key, parameter.Value);
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
        /// Gets or sets the "code" parameter.
        /// </summary>
        public string Code {
            get { return GetParameter<string>(OpenIdConnectConstants.Parameters.Code); }
            set { SetParameter(OpenIdConnectConstants.Parameters.Code, value); }
        }

        /// <summary>
        /// Gets or sets the "error" parameter.
        /// </summary>
        public string Error {
            get { return GetParameter<string>(OpenIdConnectConstants.Parameters.Error); }
            set { SetParameter(OpenIdConnectConstants.Parameters.Error, value); }
        }

        /// <summary>
        /// Gets or sets the "error_description" parameter.
        /// </summary>
        public string ErrorDescription {
            get { return GetParameter<string>(OpenIdConnectConstants.Parameters.ErrorDescription); }
            set { SetParameter(OpenIdConnectConstants.Parameters.ErrorDescription, value); }
        }

        /// <summary>
        /// Gets or sets the "error_uri" parameter.
        /// </summary>
        public string ErrorUri {
            get { return GetParameter<string>(OpenIdConnectConstants.Parameters.ErrorUri); }
            set { SetParameter(OpenIdConnectConstants.Parameters.ErrorUri, value); }
        }

        /// <summary>
        /// Gets or sets the "expires_in" parameter.
        /// </summary>
        public long ExpiresIn {
            get { return GetParameter<long>(OpenIdConnectConstants.Parameters.ExpiresIn); }
            set { SetParameter(OpenIdConnectConstants.Parameters.ExpiresIn, value); }
        }

        /// <summary>
        /// Gets or sets the "id_token" parameter.
        /// </summary>
        public string IdToken {
            get { return GetParameter<string>(OpenIdConnectConstants.Parameters.IdToken); }
            set { SetParameter(OpenIdConnectConstants.Parameters.IdToken, value); }
        }

        /// <summary>
        /// Gets or sets the "post_logout_redirect_uri" parameter.
        /// </summary>
        public string PostLogoutRedirectUri {
            get { return GetParameter<string>(OpenIdConnectConstants.Parameters.PostLogoutRedirectUri); }
            set { SetParameter(OpenIdConnectConstants.Parameters.PostLogoutRedirectUri, value); }
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
        /// Gets or sets the "resource" parameter.
        /// </summary>
        public string Resource {
            get { return GetParameter<string>(OpenIdConnectConstants.Parameters.Resource); }
            set { SetParameter(OpenIdConnectConstants.Parameters.Resource, value); }
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
        /// Gets or sets the "token_type" parameter.
        /// </summary>
        public string TokenType {
            get { return GetParameter<string>(OpenIdConnectConstants.Parameters.TokenType); }
            set { SetParameter(OpenIdConnectConstants.Parameters.TokenType, value); }
        }

        /// <summary>
        /// Gets or sets an OpenID Connect response parameter.
        /// </summary>
        /// <param name="name">The parameter name.</param>
        /// <returns>The parameter value.</returns>
        public JToken this[string name] {
            get { return GetParameter(name); }
            set { SetParameter(name, value); }
        }

        /// <summary>
        /// Gets the dictionary containing the OpenID Connect response parameters.
        /// </summary>
        protected internal virtual Dictionary<string, JToken> Parameters { get; } =
            new Dictionary<string, JToken>(StringComparer.Ordinal);

        /// <summary>
        /// Gets an enumerator allowing to iterate the parameter details.
        /// </summary>
        /// <returns>An enumerator.</returns>
        public IEnumerator<KeyValuePair<string, JToken>> GetEnumerator() {
            return Parameters.GetEnumerator();
        }

        /// <summary>
        /// Gets the value corresponding to a given OpenID Connect response parameter.
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
        /// Gets the value corresponding to a given OpenID Connect response parameter.
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

            return parameter.Value<T>();
        }

        /// <summary>
        /// Adds, replaces or removes an OpenID Connect response parameter.
        /// </summary>
        /// <param name="name">The parameter name.</param>
        /// <param name="value">The parameter value.</param>
        /// <returns>The current OpenID Connect response.</returns>
        public virtual OpenIdConnectResponse SetParameter([NotNull] string name, JToken value) {
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
        /// Gets the parameter names contained in this response.
        /// </summary>
        ICollection<string> IDictionary<string, JToken>.Keys => Parameters.Keys;

        /// <summary>
        /// Gets the parameter values contained in this response.
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
        /// Gets a boolean indicating whether a parameter exists in the current response.
        /// </summary>
        /// <param name="key">The parameter name.</param>
        /// <returns><c>true</c> if the parameter exists, <c>false</c> otherwise.</returns>
        bool IDictionary<string, JToken>.ContainsKey(string key) => Parameters.ContainsKey(key);

        /// <summary>
        /// Adds a new parameter in the current response.
        /// </summary>
        /// <param name="key">The parameter name.</param>
        /// <param name="value">The parameter value.</param>
        void IDictionary<string, JToken>.Add(string key, JToken value) => SetParameter(key, value);

        /// <summary>
        /// Removes a parameter from the current response.
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
        /// Gets the number of parameters contained in this response.
        /// </summary>
        int ICollection<KeyValuePair<string, JToken>>.Count => Parameters.Count;

        /// <summary>
        /// Gets a boolean indicating whether this response is read-only.
        /// </summary>
        bool ICollection<KeyValuePair<string, JToken>>.IsReadOnly => false;

        /// <summary>
        /// Adds a new parameter in the current response.
        /// </summary>
        /// <param name="item">The parameter details.</param>
        void ICollection<KeyValuePair<string, JToken>>.Add(KeyValuePair<string, JToken> item) {
            SetParameter(item.Key, item.Value);
        }

        /// <summary>
        /// Clears the parameters contained in this response.
        /// </summary>
        void ICollection<KeyValuePair<string, JToken>>.Clear() => Parameters.Clear();

        /// <summary>
        /// Gets a boolean indicating whether a parameter exists in the current response.
        /// </summary>
        /// <param name="item">The parameter details.</param>
        /// <returns><c>true</c> if the parameter exists, <c>false</c> otherwise.</returns>
        bool ICollection<KeyValuePair<string, JToken>>.Contains(KeyValuePair<string, JToken> item) {
            return (Parameters as ICollection<KeyValuePair<string, JToken>>).Contains(item);
        }

        /// <summary>
        /// Copies the current response paramaters to a given array.
        /// </summary>
        /// <param name="array">The array the parameters are copied to.</param>
        /// <param name="index">The zero-based index in array at which copying begins.</param>
        void ICollection<KeyValuePair<string, JToken>>.CopyTo(KeyValuePair<string, JToken>[] array, int index) {
            (Parameters as ICollection<KeyValuePair<string, JToken>>).CopyTo(array, index);
        }

        /// <summary>
        /// Removes a parameter from the current response.
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
