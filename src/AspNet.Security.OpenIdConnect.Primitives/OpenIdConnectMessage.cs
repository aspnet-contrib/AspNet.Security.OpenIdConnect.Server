/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using JetBrains.Annotations;
using Microsoft.Extensions.Primitives;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace AspNet.Security.OpenIdConnect.Primitives {
    /// <summary>
    /// Represents an abstract OpenID Connect message.
    /// </summary>
    [DebuggerDisplay("Parameters: {Parameters.Count}")]
    [JsonObject(MemberSerialization = MemberSerialization.OptIn)]
    public abstract class OpenIdConnectMessage {
        /// <summary>
        /// Initializes a new OpenID Connect message.
        /// </summary>
        protected OpenIdConnectMessage() { }

        /// <summary>
        /// Initializes a new OpenID Connect message.
        /// </summary>
        /// <param name="payload">The message payload.</param>
        protected OpenIdConnectMessage([NotNull] JObject payload) {
            if (payload == null) {
                throw new ArgumentNullException(nameof(payload));
            }

            foreach (var parameter in payload.Properties()) {
                SetParameter(parameter.Name, parameter.Value);
            }
        }

        /// <summary>
        /// Initializes a new OpenID Connect message.
        /// </summary>
        /// <param name="parameters">The message parameters.</param>
        protected OpenIdConnectMessage([NotNull] IDictionary<string, string> parameters) {
            if (parameters == null) {
                throw new ArgumentNullException(nameof(parameters));
            }

            foreach (var parameter in parameters) {
                SetParameter(parameter.Key, parameter.Value);
            }
        }

        /// <summary>
        /// Initializes a new OpenID Connect message.
        /// </summary>
        /// <param name="parameters">The message parameters.</param>
        protected OpenIdConnectMessage([NotNull] IDictionary<string, JToken> parameters) {
            if (parameters == null) {
                throw new ArgumentNullException(nameof(parameters));
            }

            foreach (var parameter in parameters) {
                SetParameter(parameter.Key, parameter.Value);
            }
        }

        /// <summary>
        /// Initializes a new OpenID Connect message.
        /// </summary>
        /// <param name="parameters">The message parameters.</param>
        protected OpenIdConnectMessage([NotNull] IEnumerable<KeyValuePair<string, string[]>> parameters) {
            if (parameters == null) {
                throw new ArgumentNullException(nameof(parameters));
            }

            foreach (var parameter in parameters) {
                SetParameter(parameter.Key, string.Join(",", parameter.Value));
            }
        }

        /// <summary>
        /// Initializes a new OpenID Connect message.
        /// </summary>
        /// <param name="parameters">The message parameters.</param>
        protected OpenIdConnectMessage([NotNull] IEnumerable<KeyValuePair<string, StringValues>> parameters) {
            if (parameters == null) {
                throw new ArgumentNullException(nameof(parameters));
            }

            foreach (var parameter in parameters) {
                SetParameter(parameter.Key, (string) parameter.Value);
            }
        }

        /// <summary>
        /// Gets or sets a parameter.
        /// </summary>
        /// <param name="name">The parameter name.</param>
        /// <returns>The parameter value.</returns>
        public JToken this[string name] {
            get { return GetParameter(name); }
            set { SetParameter(name, value); }
        }

        /// <summary>
        /// Gets the dictionary containing the parameters.
        /// </summary>
        [JsonExtensionData]
        protected virtual Dictionary<string, JToken> Parameters { get; } =
            new Dictionary<string, JToken>(StringComparer.Ordinal);

        /// <summary>
        /// Gets the dictionary containing the properties associated with this OpenID Connect message.
        /// Note: these properties are not meant to be publicly shared and shouldn't be serialized.
        /// </summary>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        protected virtual Dictionary<string, string> Properties { get; } =
            new Dictionary<string, string>(StringComparer.Ordinal);

        /// <summary>
        /// Gets the value corresponding to a given parameter.
        /// </summary>
        /// <param name="name">The parameter name.</param>
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
        /// Gets the value corresponding to a given parameter.
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
        /// Gets all the parameters associated with this instance.
        /// </summary>
        /// <returns>The parameters associated with this instance.</returns>
        public virtual IEnumerable<KeyValuePair<string, JToken>> GetParameters() {
            foreach (var parameter in Parameters) {
                yield return parameter;
            }

            yield break;
        }

        /// <summary>
        /// Gets all the properties associated with this instance.
        /// </summary>
        /// <returns>The properties associated with this instance.</returns>
        public virtual IEnumerable<KeyValuePair<string, string>> GetProperties() {
            foreach (var property in Properties) {
                yield return property;
            }

            yield break;
        }

        /// <summary>
        /// Gets the value corresponding to a given property associated with this message.
        /// </summary>
        /// <param name="name">The property name.</param>
        /// <returns>The property value, or <c>null</c> if it cannot be found.</returns>
        [EditorBrowsable(EditorBrowsableState.Never)]
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
        /// Determines whether the current message contains the specified parameter.
        /// </summary>
        /// <param name="name">The parameter name.</param>
        /// <returns><c>true</c> if the parameter is present, <c>false</c> otherwise.</returns>
        public virtual bool HasParameter([NotNull] string name) {
            if (string.IsNullOrEmpty(name)) {
                throw new ArgumentException("The parameter name cannot be null or empty.", nameof(name));
            }

            return Parameters.ContainsKey(name);
        }

        /// <summary>
        /// Determines whether the current message contains the specified property.
        /// </summary>
        /// <param name="name">The property name.</param>
        /// <returns><c>true</c> if the property is present, <c>false</c> otherwise.</returns>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public virtual bool HasProperty([NotNull] string name) {
            if (string.IsNullOrEmpty(name)) {
                throw new ArgumentException("The property name cannot be null or empty.", nameof(name));
            }

            return Properties.ContainsKey(name);
        }

        /// <summary>
        /// Adds, replaces or removes a parameter.
        /// </summary>
        /// <param name="name">The parameter name.</param>
        /// <param name="value">The parameter value.</param>
        public virtual void SetParameter([NotNull] string name, JToken value) {
            if (string.IsNullOrEmpty(name)) {
                throw new ArgumentException("The parameter name cannot be null or empty.", nameof(name));
            }

            // If the parameter value is null, remove the corresponding entry in the collection.
            if (value == null || (value.Type == JTokenType.Array && !value.HasValues) ||
                                 (value.Type == JTokenType.Object && !value.HasValues) ||
                                 (value.Type == JTokenType.String && string.IsNullOrEmpty((string) value)) ||
                                 (value.Type == JTokenType.Null)) {
                Parameters.Remove(name);

                return;
            }

            Parameters[name] = value;
        }

        /// <summary>
        /// Adds, replaces or removes a property.
        /// </summary>
        /// <param name="name">The property name.</param>
        /// <param name="value">The property value.</param>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public virtual void SetProperty([NotNull] string name, string value) {
            if (string.IsNullOrEmpty(name)) {
                throw new ArgumentException("The property name cannot be null or empty.", nameof(name));
            }

            // If the property value is null, remove the corresponding entry in the collection.
            if (value == null || string.IsNullOrEmpty(value)) {
                Properties.Remove(name);

                return;
            }

            Properties[name] = value;
        }
    }
}
