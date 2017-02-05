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
    [JsonConverter(typeof(OpenIdConnectConverter))]
    public abstract class OpenIdConnectMessage {
        /// <summary>
        /// Initializes a new OpenID Connect message.
        /// </summary>
        protected OpenIdConnectMessage() { }

        /// <summary>
        /// Initializes a new OpenID Connect message.
        /// </summary>
        /// <param name="parameters">The message parameters.</param>
        protected OpenIdConnectMessage([NotNull] IEnumerable<KeyValuePair<string, JToken>> parameters) {
            if (parameters == null) {
                throw new ArgumentNullException(nameof(parameters));
            }

            foreach (var parameter in parameters) {
                if (string.IsNullOrEmpty(parameter.Key)) {
                    continue;
                }

                AddParameter(parameter.Key, parameter.Value);
            }
        }

        /// <summary>
        /// Initializes a new OpenID Connect message.
        /// </summary>
        /// <param name="parameters">The message parameters.</param>
        protected OpenIdConnectMessage([NotNull] IEnumerable<KeyValuePair<string, OpenIdConnectParameter>> parameters) {
            if (parameters == null) {
                throw new ArgumentNullException(nameof(parameters));
            }

            foreach (var parameter in parameters) {
                if (string.IsNullOrEmpty(parameter.Key)) {
                    continue;
                }

                AddParameter(parameter.Key, parameter.Value);
            }
        }

        /// <summary>
        /// Initializes a new OpenID Connect message.
        /// </summary>
        /// <param name="parameters">The message parameters.</param>
        protected OpenIdConnectMessage([NotNull] IEnumerable<KeyValuePair<string, string>> parameters) {
            if (parameters == null) {
                throw new ArgumentNullException(nameof(parameters));
            }

            foreach (var parameter in parameters) {
                if (string.IsNullOrEmpty(parameter.Key)) {
                    continue;
                }

                AddParameter(parameter.Key, parameter.Value);
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
                if (string.IsNullOrEmpty(parameter.Key)) {
                    continue;
                }

                AddParameter(parameter.Key, string.Join(",", parameter.Value));
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
                if (string.IsNullOrEmpty(parameter.Key)) {
                    continue;
                }

                AddParameter(parameter.Key, (string) parameter.Value);
            }
        }

        /// <summary>
        /// Gets or sets a parameter.
        /// </summary>
        /// <param name="name">The parameter name.</param>
        /// <returns>The parameter value.</returns>
        public OpenIdConnectParameter? this[string name] {
            get { return GetParameter(name); }
            set { SetParameter(name, value); }
        }

        /// <summary>
        /// Gets the dictionary containing the parameters.
        /// </summary>
        protected Dictionary<string, OpenIdConnectParameter> Parameters { get; } =
            new Dictionary<string, OpenIdConnectParameter>(StringComparer.Ordinal);

        /// <summary>
        /// Gets the dictionary containing the properties associated with this OpenID Connect message.
        /// Note: these properties are not meant to be publicly shared and shouldn't be serialized.
        /// </summary>
        [EditorBrowsable(EditorBrowsableState.Never)]
        protected Dictionary<string, object> Properties { get; } =
            new Dictionary<string, object>(StringComparer.Ordinal);

        /// <summary>
        /// Adds a parameter.
        /// </summary>
        /// <param name="name">The parameter name.</param>
        /// <param name="value">The parameter value.</param>
        /// <returns>The current instance, which allows chaining calls.</returns>
        public OpenIdConnectMessage AddParameter([NotNull] string name, OpenIdConnectParameter value) {
            if (string.IsNullOrEmpty(name)) {
                throw new ArgumentException("The parameter name cannot be null or empty.", nameof(name));
            }

            if (!Parameters.ContainsKey(name)) {
                Parameters.Add(name, value);
            }

            return this;
        }

        /// <summary>
        /// Adds a property.
        /// </summary>
        /// <param name="name">The property name.</param>
        /// <param name="value">The property value.</param>
        /// <returns>The current instance, which allows chaining calls.</returns>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public OpenIdConnectMessage AddProperty([NotNull] string name, [CanBeNull] object value) {
            if (string.IsNullOrEmpty(name)) {
                throw new ArgumentException("The property name cannot be null or empty.", nameof(name));
            }

            if (!Properties.ContainsKey(name)) {
                Properties.Add(name, value);
            }

            return this;
        }

        /// <summary>
        /// Gets the value corresponding to a given parameter.
        /// </summary>
        /// <param name="name">The parameter name.</param>
        /// <returns>The parameter value, or <c>null</c> if it cannot be found.</returns>
        public OpenIdConnectParameter? GetParameter([NotNull] string name) {
            if (string.IsNullOrEmpty(name)) {
                throw new ArgumentException("The parameter name cannot be null or empty.", nameof(name));
            }

            OpenIdConnectParameter value;
            if (Parameters.TryGetValue(name, out value)) {
                return value;
            }

            return null;
        }

        /// <summary>
        /// Gets all the parameters associated with this instance.
        /// </summary>
        /// <returns>The parameters associated with this instance.</returns>
        public IEnumerable<KeyValuePair<string, OpenIdConnectParameter>> GetParameters() {
            foreach (var parameter in Parameters) {
                yield return parameter;
            }

            yield break;
        }

        /// <summary>
        /// Gets all the properties associated with this instance.
        /// </summary>
        /// <returns>The properties associated with this instance.</returns>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public IEnumerable<KeyValuePair<string, object>> GetProperties() {
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
        public object GetProperty([NotNull] string name) {
            if (string.IsNullOrEmpty(name)) {
                throw new ArgumentException("The property name cannot be null or empty.", nameof(name));
            }

            object value;
            if (Properties.TryGetValue(name, out value)) {
                return value;
            }

            return null;
        }

        /// <summary>
        /// Gets the value corresponding to a given property associated with this message.
        /// </summary>
        /// <typeparam name="T">The type of the property.</typeparam>
        /// <param name="name">The property name.</param>
        /// <returns>The property value, or <c>null</c> if it cannot be found.</returns>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public T GetProperty<T>([NotNull] string name) {
            if (string.IsNullOrEmpty(name)) {
                throw new ArgumentException("The property name cannot be null or empty.", nameof(name));
            }

            object value;
            if (Properties.TryGetValue(name, out value) && value is T) {
                return (T) value;
            }

            return default(T);
        }

        /// <summary>
        /// Determines whether the current message contains the specified parameter.
        /// </summary>
        /// <param name="name">The parameter name.</param>
        /// <returns><c>true</c> if the parameter is present, <c>false</c> otherwise.</returns>
        public bool HasParameter([NotNull] string name) {
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
        public bool HasProperty([NotNull] string name) {
            if (string.IsNullOrEmpty(name)) {
                throw new ArgumentException("The property name cannot be null or empty.", nameof(name));
            }

            return Properties.ContainsKey(name);
        }

        /// <summary>
        /// Removes a parameter.
        /// </summary>
        /// <param name="name">The parameter name.</param>
        /// <returns>The current instance, which allows chaining calls.</returns>
        public OpenIdConnectMessage RemoveParameter([NotNull] string name) {
            if (string.IsNullOrEmpty(name)) {
                throw new ArgumentException("The parameter name cannot be null or empty.", nameof(name));
            }

            Parameters.Remove(name);

            return this;
        }

        /// <summary>
        /// Removes a property.
        /// </summary>
        /// <param name="name">The property name.</param>
        /// <returns>The current instance, which allows chaining calls.</returns>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public OpenIdConnectMessage RemoveProperty([NotNull] string name) {
            if (string.IsNullOrEmpty(name)) {
                throw new ArgumentException("The property name cannot be null or empty.", nameof(name));
            }

            Properties.Remove(name);

            return this;
        }

        /// <summary>
        /// Adds, replaces or removes a parameter.
        /// Note: this method automatically removes empty parameters.
        /// </summary>
        /// <param name="name">The parameter name.</param>
        /// <param name="value">The parameter value.</param>
        /// <returns>The current instance, which allows chaining calls.</returns>
        public OpenIdConnectMessage SetParameter([NotNull] string name, [CanBeNull] OpenIdConnectParameter? value) {
            if (string.IsNullOrEmpty(name)) {
                throw new ArgumentException("The parameter name cannot be null or empty.", nameof(name));
            }

            // If the parameter value is null or empty,
            // remove the corresponding entry from the collection.
            if (value == null || OpenIdConnectParameter.IsNullOrEmpty(value.GetValueOrDefault())) {
                Parameters.Remove(name);
            }

            else {
                Parameters[name] = value.GetValueOrDefault();
            }

            return this;
        }

        /// <summary>
        /// Adds, replaces or removes a property.
        /// Note: this method automatically removes empty parameters.
        /// </summary>
        /// <param name="name">The property name.</param>
        /// <param name="value">The property value.</param>
        /// <returns>The current instance, which allows chaining calls.</returns>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public OpenIdConnectMessage SetProperty([NotNull] string name, [CanBeNull] object value) {
            if (string.IsNullOrEmpty(name)) {
                throw new ArgumentException("The property name cannot be null or empty.", nameof(name));
            }

            // If the property value is null, remove the
            // corresponding entry from the collection.
            if (value == null || (value is string && string.IsNullOrEmpty((string) value))) {
                Properties.Remove(name);
            }

            else {
                Properties[name] = value;
            }

            return this;
        }
    }
}
