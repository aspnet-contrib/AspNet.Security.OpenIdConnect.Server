/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Text;
using JetBrains.Annotations;
using Microsoft.Extensions.Primitives;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace AspNet.Security.OpenIdConnect.Primitives
{
    /// <summary>
    /// Represents an abstract OpenID Connect message.
    /// </summary>
    /// <remarks>
    /// Security notice: developers instantiating this type are responsible of ensuring that the
    /// imported parameters are safe and won't cause the resulting message to grow abnormally,
    /// which may result in an excessive memory consumption and a potential denial of service.
    /// </remarks>
    [DebuggerDisplay("Parameters: {Parameters.Count}")]
    [JsonConverter(typeof(OpenIdConnectConverter))]
    public class OpenIdConnectMessage
    {
        /// <summary>
        /// Initializes a new OpenID Connect message.
        /// </summary>
        public OpenIdConnectMessage() { }

        /// <summary>
        /// Initializes a new OpenID Connect message.
        /// </summary>
        /// <param name="parameters">The message parameters.</param>
        public OpenIdConnectMessage([NotNull] IEnumerable<KeyValuePair<string, JToken>> parameters)
        {
            if (parameters == null)
            {
                throw new ArgumentNullException(nameof(parameters));
            }

            foreach (var parameter in parameters)
            {
                if (string.IsNullOrEmpty(parameter.Key))
                {
                    continue;
                }

                AddParameter(parameter.Key, parameter.Value);
            }
        }

        /// <summary>
        /// Initializes a new OpenID Connect message.
        /// </summary>
        /// <param name="parameters">The message parameters.</param>
        public OpenIdConnectMessage([NotNull] IEnumerable<KeyValuePair<string, OpenIdConnectParameter>> parameters)
        {
            if (parameters == null)
            {
                throw new ArgumentNullException(nameof(parameters));
            }

            foreach (var parameter in parameters)
            {
                if (string.IsNullOrEmpty(parameter.Key))
                {
                    continue;
                }

                AddParameter(parameter.Key, parameter.Value);
            }
        }

        /// <summary>
        /// Initializes a new OpenID Connect message.
        /// </summary>
        /// <param name="parameters">The message parameters.</param>
        public OpenIdConnectMessage([NotNull] IEnumerable<KeyValuePair<string, string>> parameters)
        {
            if (parameters == null)
            {
                throw new ArgumentNullException(nameof(parameters));
            }

            foreach (var parameter in parameters)
            {
                if (string.IsNullOrEmpty(parameter.Key))
                {
                    continue;
                }

                AddParameter(parameter.Key, parameter.Value);
            }
        }

        /// <summary>
        /// Initializes a new OpenID Connect message.
        /// </summary>
        /// <param name="parameters">The message parameters.</param>
        public OpenIdConnectMessage([NotNull] IEnumerable<KeyValuePair<string, string[]>> parameters)
        {
            if (parameters == null)
            {
                throw new ArgumentNullException(nameof(parameters));
            }

            foreach (var parameter in parameters)
            {
                if (string.IsNullOrEmpty(parameter.Key))
                {
                    continue;
                }

                // Note: the core OAuth2 specification requires that request parameters
                // not be present more than once but derived specifications like the
                // token exchange RFC deliberately allow specifying multiple resource
                // parameters with the same name to represent a multi-valued parameter.
                switch (parameter.Value?.Length ?? 0)
                {
                    case 0:  AddParameter(parameter.Key, default);            break;
                    case 1:  AddParameter(parameter.Key, parameter.Value[0]); break;
                    default: AddParameter(parameter.Key, parameter.Value);    break;
                }
            }
        }

        /// <summary>
        /// Initializes a new OpenID Connect message.
        /// </summary>
        /// <param name="parameters">The message parameters.</param>
        public OpenIdConnectMessage([NotNull] IEnumerable<KeyValuePair<string, StringValues>> parameters)
        {
            if (parameters == null)
            {
                throw new ArgumentNullException(nameof(parameters));
            }

            foreach (var parameter in parameters)
            {
                if (string.IsNullOrEmpty(parameter.Key))
                {
                    continue;
                }

                // Note: the core OAuth2 specification requires that request parameters
                // not be present more than once but derived specifications like the
                // token exchange RFC deliberately allow specifying multiple resource
                // parameters with the same name to represent a multi-valued parameter.
                switch (parameter.Value.Count)
                {
                    case 0:  AddParameter(parameter.Key, default);                   break;
                    case 1:  AddParameter(parameter.Key, parameter.Value[0]);        break;
                    default: AddParameter(parameter.Key, parameter.Value.ToArray()); break;
                }
            }
        }

        /// <summary>
        /// Gets or sets a parameter.
        /// </summary>
        /// <param name="name">The parameter name.</param>
        /// <returns>The parameter value.</returns>
        public OpenIdConnectParameter? this[string name]
        {
            get => GetParameter(name);
            set => SetParameter(name, value);
        }

        /// <summary>
        /// Gets the dictionary containing the parameters.
        /// </summary>
        protected Dictionary<string, OpenIdConnectParameter> Parameters { get; }
            = new Dictionary<string, OpenIdConnectParameter>(StringComparer.Ordinal);

        /// <summary>
        /// Gets the dictionary containing the properties associated with this OpenID Connect message.
        /// Note: these properties are not meant to be publicly shared and shouldn't be serialized.
        /// </summary>
        [EditorBrowsable(EditorBrowsableState.Never)]
        protected Dictionary<string, object> Properties { get; }
            = new Dictionary<string, object>(StringComparer.Ordinal);

        /// <summary>
        /// Adds a parameter.
        /// </summary>
        /// <param name="name">The parameter name.</param>
        /// <param name="value">The parameter value.</param>
        /// <returns>The current instance, which allows chaining calls.</returns>
        public OpenIdConnectMessage AddParameter([NotNull] string name, OpenIdConnectParameter value)
        {
            if (string.IsNullOrEmpty(name))
            {
                throw new ArgumentException("The parameter name cannot be null or empty.", nameof(name));
            }

            if (!Parameters.ContainsKey(name))
            {
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
        public OpenIdConnectMessage AddProperty([NotNull] string name, [CanBeNull] object value)
        {
            if (string.IsNullOrEmpty(name))
            {
                throw new ArgumentException("The property name cannot be null or empty.", nameof(name));
            }

            if (!Properties.ContainsKey(name))
            {
                Properties.Add(name, value);
            }

            return this;
        }

        /// <summary>
        /// Gets the value corresponding to a given parameter.
        /// </summary>
        /// <param name="name">The parameter name.</param>
        /// <returns>The parameter value, or <c>null</c> if it cannot be found.</returns>
        public OpenIdConnectParameter? GetParameter([NotNull] string name)
        {
            if (string.IsNullOrEmpty(name))
            {
                throw new ArgumentException("The parameter name cannot be null or empty.", nameof(name));
            }

            if (Parameters.TryGetValue(name, out OpenIdConnectParameter value))
            {
                return value;
            }

            return null;
        }

        /// <summary>
        /// Gets all the parameters associated with this instance.
        /// </summary>
        /// <returns>The parameters associated with this instance.</returns>
        public IEnumerable<KeyValuePair<string, OpenIdConnectParameter>> GetParameters()
        {
            foreach (var parameter in Parameters)
            {
                yield return parameter;
            }

            yield break;
        }

        /// <summary>
        /// Gets all the properties associated with this instance.
        /// </summary>
        /// <returns>The properties associated with this instance.</returns>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public IEnumerable<KeyValuePair<string, object>> GetProperties()
        {
            foreach (var property in Properties)
            {
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
        public object GetProperty([NotNull] string name)
        {
            if (string.IsNullOrEmpty(name))
            {
                throw new ArgumentException("The property name cannot be null or empty.", nameof(name));
            }

            if (Properties.TryGetValue(name, out object value))
            {
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
        public T GetProperty<T>([NotNull] string name)
        {
            if (string.IsNullOrEmpty(name))
            {
                throw new ArgumentException("The property name cannot be null or empty.", nameof(name));
            }

            if (Properties.TryGetValue(name, out object value) && value is T)
            {
                return (T) value;
            }

            return default;
        }

        /// <summary>
        /// Determines whether the current message contains the specified parameter.
        /// </summary>
        /// <param name="name">The parameter name.</param>
        /// <returns><c>true</c> if the parameter is present, <c>false</c> otherwise.</returns>
        public bool HasParameter([NotNull] string name)
        {
            if (string.IsNullOrEmpty(name))
            {
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
        public bool HasProperty([NotNull] string name)
        {
            if (string.IsNullOrEmpty(name))
            {
                throw new ArgumentException("The property name cannot be null or empty.", nameof(name));
            }

            return Properties.ContainsKey(name);
        }

        /// <summary>
        /// Removes a parameter.
        /// </summary>
        /// <param name="name">The parameter name.</param>
        /// <returns>The current instance, which allows chaining calls.</returns>
        public OpenIdConnectMessage RemoveParameter([NotNull] string name)
        {
            if (string.IsNullOrEmpty(name))
            {
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
        public OpenIdConnectMessage RemoveProperty([NotNull] string name)
        {
            if (string.IsNullOrEmpty(name))
            {
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
        public OpenIdConnectMessage SetParameter([NotNull] string name, [CanBeNull] OpenIdConnectParameter? value)
        {
            if (string.IsNullOrEmpty(name))
            {
                throw new ArgumentException("The parameter name cannot be null or empty.", nameof(name));
            }

            // If the parameter value is null or empty,
            // remove the corresponding entry from the collection.
            if (value == null || OpenIdConnectParameter.IsNullOrEmpty(value.GetValueOrDefault()))
            {
                Parameters.Remove(name);
            }

            else
            {
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
        public OpenIdConnectMessage SetProperty([NotNull] string name, [CanBeNull] object value)
        {
            if (string.IsNullOrEmpty(name))
            {
                throw new ArgumentException("The property name cannot be null or empty.", nameof(name));
            }

            // If the property value is null, remove the corresponding entry from the collection.
            if (value == null || (value is string text && string.IsNullOrEmpty(text)))
            {
                Properties.Remove(name);
            }

            else
            {
                Properties[name] = value;
            }

            return this;
        }

        /// <summary>
        /// Returns a <see cref="string"/> representation of the current instance that can be used in logs.
        /// Note: sensitive parameters like client secrets are automatically removed for security reasons.
        /// </summary>
        /// <returns>The indented JSON representation corresponding to this message.</returns>
        public override string ToString()
        {
            var builder = new StringBuilder();

            using (var writer = new JsonTextWriter(new StringWriter(builder, CultureInfo.InvariantCulture)))
            {
                writer.Formatting = Formatting.Indented;

                writer.WriteStartObject();

                foreach (var parameter in Parameters)
                {
                    writer.WritePropertyName(parameter.Key);

                    // Remove sensitive parameters from the generated payload.
                    switch (parameter.Key)
                    {
                        case OpenIdConnectConstants.Parameters.AccessToken:
                        case OpenIdConnectConstants.Parameters.Assertion:
                        case OpenIdConnectConstants.Parameters.ClientAssertion:
                        case OpenIdConnectConstants.Parameters.ClientSecret:
                        case OpenIdConnectConstants.Parameters.Code:
                        case OpenIdConnectConstants.Parameters.IdToken:
                        case OpenIdConnectConstants.Parameters.IdTokenHint:
                        case OpenIdConnectConstants.Parameters.Password:
                        case OpenIdConnectConstants.Parameters.RefreshToken:
                        case OpenIdConnectConstants.Parameters.Token:
                        {
                            writer.WriteValue("[removed for security reasons]");

                            continue;
                        }
                    }

                    var token = (JToken) parameter.Value;
                    if (token == null)
                    {
                        writer.WriteNull();

                        continue;
                    }

                    token.WriteTo(writer);
                }

                writer.WriteEndObject();
            }

            return builder.ToString();
        }
    }
}
