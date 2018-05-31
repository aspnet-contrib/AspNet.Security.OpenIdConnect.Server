/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using JetBrains.Annotations;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace AspNet.Security.OpenIdConnect.Primitives
{
    /// <summary>
    /// Represents an OpenID Connect parameter value, that can be either a primitive value,
    /// an array of strings or a complex JSON representation containing child nodes.
    /// </summary>
    public readonly struct OpenIdConnectParameter : IEquatable<OpenIdConnectParameter>
    {
        /// <summary>
        /// Initializes a new OpenID Connect
        /// parameter using the specified value.
        /// </summary>
        /// <param name="value">The parameter value.</param>
        public OpenIdConnectParameter(bool value) => Value = value;

        /// <summary>
        /// Initializes a new OpenID Connect
        /// parameter using the specified value.
        /// </summary>
        /// <param name="value">The parameter value.</param>
        public OpenIdConnectParameter(bool? value) => Value = value;

        /// <summary>
        /// Initializes a new OpenID Connect
        /// parameter using the specified value.
        /// </summary>
        /// <param name="value">The parameter value.</param>
        public OpenIdConnectParameter(JToken value) => Value = value;

        /// <summary>
        /// Initializes a new OpenID Connect
        /// parameter using the specified value.
        /// </summary>
        /// <param name="value">The parameter value.</param>
        public OpenIdConnectParameter(long value) => Value = value;

        /// <summary>
        /// Initializes a new OpenID Connect
        /// parameter using the specified value.
        /// </summary>
        /// <param name="value">The parameter value.</param>
        public OpenIdConnectParameter(long? value) => Value = value;

        /// <summary>
        /// Initializes a new OpenID Connect
        /// parameter using the specified value.
        /// </summary>
        /// <param name="value">The parameter value.</param>
        public OpenIdConnectParameter(string value) => Value = value;

        /// <summary>
        /// Initializes a new OpenID Connect
        /// parameter using the specified value.
        /// </summary>
        /// <param name="value">The parameter value.</param>
        public OpenIdConnectParameter(string[] value) => Value = value;

        /// <summary>
        /// Gets the child item corresponding to the specified index.
        /// </summary>
        /// <param name="index">The index of the child item.</param>
        /// <returns>An <see cref="OpenIdConnectParameter"/> instance containing the item value.</returns>
        public OpenIdConnectParameter? this[int index] => GetParameter(index);

        /// <summary>
        /// Gets the child item corresponding to the specified name.
        /// </summary>
        /// <param name="name">The name of the child item.</param>
        /// <returns>An <see cref="OpenIdConnectParameter"/> instance containing the item value.</returns>
        public OpenIdConnectParameter? this[string name] => GetParameter(name);

        /// <summary>
        /// Gets the associated value, that can be either a primitive CLR type
        /// (e.g bool, string, long), an array of strings or a complex JSON object.
        /// </summary>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        public object Value { get; }

        /// <summary>
        /// Determines whether the current <see cref="OpenIdConnectParameter"/>
        /// instance is equal to the specified <see cref="OpenIdConnectParameter"/>.
        /// </summary>
        /// <param name="parameter">The other object to which to compare this instance.</param>
        /// <returns><c>true</c> if the two instances are equal, <c>false</c> otherwise.</returns>
        public bool Equals(OpenIdConnectParameter parameter)
        {
            switch (Value)
            {
                // If the two parameters reference the same instance, return true.
                // Note: true will also be returned if the two parameters are null.
                case var value when ReferenceEquals(value, parameter.Value):
                    return true;

                // If one of the two parameters is null, return false.
                case null:
                case var _ when parameter.Value == null:
                    return false;

                // If the two parameters are string arrays, use SequenceEqual().
                case string[] array when parameter.Value is string[] other:
                    return array.SequenceEqual(other);

                // If the two parameters are JSON values, use JToken.DeepEquals().
                case JToken token when parameter.Value is JToken other:
                    return JToken.DeepEquals(token, other);

                // If the current instance is a JValue, compare the
                // underlying value to the other parameter value.
                case JValue value:
                    return value.Value != null && value.Value.Equals(parameter.Value);

                // If the other parameter is a JValue, compare the
                // underlying value to the current parameter value.
                case var value when parameter.Value is JValue other:
                    return other.Value != null && other.Value.Equals(value);

                // Otherwise, directly compare the two underlying values.
                default:
                    return Value.Equals(parameter.Value);
            }
        }

        /// <summary>
        /// Determines whether the current <see cref="OpenIdConnectParameter"/>
        /// instance is equal to the specified <see cref="object"/>.
        /// </summary>
        /// <param name="value">The other object to which to compare this instance.</param>
        /// <returns><c>true</c> if the two instances are equal, <c>false</c> otherwise.</returns>
        public override bool Equals(object value)
            => value is OpenIdConnectParameter parameter && Equals(parameter);

        /// <summary>
        /// Returns the hash code of the current <see cref="OpenIdConnectParameter"/> instance.
        /// </summary>
        /// <returns>The hash code for the current instance.</returns>
        // Note: if the value is a JValue, JSON.NET will automatically
        // return the hash code corresponding to the underlying value.
        public override int GetHashCode() => Value?.GetHashCode() ?? 0;

        /// <summary>
        /// Gets the child item corresponding to the specified index.
        /// </summary>
        /// <param name="index">The index of the child item.</param>
        /// <returns>An <see cref="OpenIdConnectParameter"/> instance containing the item value.</returns>
        public OpenIdConnectParameter? GetParameter(int index)
        {
            if (index < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(index), "The item index cannot be negative.");
            }

            if (Value is string[] array)
            {
                // If the specified index goes beyond the
                // number of items in the array, return null.
                if (index >= array.Length)
                {
                    return null;
                }

                return new OpenIdConnectParameter(array[index]);
            }

            // If the value is not a JSON array, return null.
            if (Value is JArray token)
            {
                // If the specified index goes beyond the
                // number of items in the array, return null.
                if (index >= token.Count)
                {
                    return null;
                }

                // If the item doesn't exist, return a null parameter.
                var value = token[index];
                if (value == null)
                {
                    return null;
                }

                return new OpenIdConnectParameter(value);
            }

            return null;
        }

        /// <summary>
        /// Gets the child item corresponding to the specified name.
        /// </summary>
        /// <param name="name">The name of the child item.</param>
        /// <returns>An <see cref="OpenIdConnectParameter"/> instance containing the item value.</returns>
        public OpenIdConnectParameter? GetParameter([NotNull] string name)
        {
            if (string.IsNullOrEmpty(name))
            {
                throw new ArgumentException("The item name cannot be null or empty.", nameof(name));
            }

            if (Value is JObject dictionary)
            {
                // If the item doesn't exist, return a null parameter.
                var value = dictionary[name];
                if (value == null)
                {
                    return null;
                }

                return new OpenIdConnectParameter(value);
            }

            return null;
        }

        /// <summary>
        /// Gets the child items associated with the current parameter.
        /// </summary>
        /// <returns>An enumeration of all the parameters associated with the current instance.</returns>
        public IEnumerable<KeyValuePair<string, OpenIdConnectParameter>> GetParameters()
        {
            if (Value is string[] array)
            {
                for (var index = 0; index < array.Length; index++)
                {
                    yield return new KeyValuePair<string, OpenIdConnectParameter>(null, array[index]);
                }
            }

            if (Value is JToken token)
            {
                foreach (var parameter in token.Children())
                {
                    var property = parameter as JProperty;
                    if (property == null)
                    {
                        yield return new KeyValuePair<string, OpenIdConnectParameter>(null, parameter);

                        continue;
                    }

                    yield return new KeyValuePair<string, OpenIdConnectParameter>(property.Name, property.Value);
                }
            }

            yield break;
        }

        /// <summary>
        /// Returns the <see cref="string"/> representation of the current instance.
        /// </summary>
        /// <returns>The <see cref="string"/> representation associated with the parameter value.</returns>
        public override string ToString()
        {
            switch (Value)
            {
                case null:
                case JValue value when value.Value == null:
                    return string.Empty;

                case string[] array:
                    return string.Join(", ", array);

                case JValue value:
                    return value.Value.ToString();

                case JToken token:
                    return token.ToString(Formatting.None);

                default:
                    return Value.ToString();
            }
        }

        /// <summary>
        /// Determines whether two <see cref="OpenIdConnectParameter"/> instances are equal.
        /// </summary>
        /// <param name="left">The first instance.</param>
        /// <param name="right">The second instance.</param>
        /// <returns><c>true</c> if the two instances are equal, <c>false</c> otherwise.</returns>
        public static bool operator ==(OpenIdConnectParameter left, OpenIdConnectParameter right) => left.Equals(right);

        /// <summary>
        /// Determines whether two <see cref="OpenIdConnectParameter"/> instances are not equal.
        /// </summary>
        /// <param name="left">The first instance.</param>
        /// <param name="right">The second instance.</param>
        /// <returns><c>true</c> if the two instances are not equal, <c>false</c> otherwise.</returns>
        public static bool operator !=(OpenIdConnectParameter left, OpenIdConnectParameter right) => !left.Equals(right);

        /// <summary>
        /// Converts an <see cref="OpenIdConnectParameter"/> instance to a boolean.
        /// </summary>
        /// <param name="parameter">The parameter to convert.</param>
        /// <returns>The converted value.</returns>
        public static explicit operator bool(OpenIdConnectParameter? parameter) => Convert<bool>(parameter);

        /// <summary>
        /// Converts an <see cref="OpenIdConnectParameter"/> instance to a nullable boolean.
        /// </summary>
        /// <param name="parameter">The parameter to convert.</param>
        /// <returns>The converted value.</returns>
        public static explicit operator bool?(OpenIdConnectParameter? parameter) => Convert<bool?>(parameter);

        /// <summary>
        /// Converts an <see cref="OpenIdConnectParameter"/> instance to a <see cref="JArray"/>.
        /// </summary>
        /// <param name="parameter">The parameter to convert.</param>
        /// <returns>The converted value.</returns>
        public static explicit operator JArray(OpenIdConnectParameter? parameter) => Convert<JArray>(parameter);

        /// <summary>
        /// Converts an <see cref="OpenIdConnectParameter"/> instance to a <see cref="JObject"/>.
        /// </summary>
        /// <param name="parameter">The parameter to convert.</param>
        /// <returns>The converted value.</returns>
        public static explicit operator JObject(OpenIdConnectParameter? parameter) => Convert<JObject>(parameter);

        /// <summary>
        /// Converts an <see cref="OpenIdConnectParameter"/> instance to a <see cref="JToken"/>.
        /// </summary>
        /// <param name="parameter">The parameter to convert.</param>
        /// <returns>The converted value.</returns>
        public static explicit operator JToken(OpenIdConnectParameter? parameter) => Convert<JToken>(parameter);

        /// <summary>
        /// Converts an <see cref="OpenIdConnectParameter"/> instance to a <see cref="JValue"/>.
        /// </summary>
        /// <param name="parameter">The parameter to convert.</param>
        /// <returns>The converted value.</returns>
        public static explicit operator JValue(OpenIdConnectParameter? parameter) => Convert<JValue>(parameter);

        /// <summary>
        /// Converts an <see cref="OpenIdConnectParameter"/> instance to a long integer.
        /// </summary>
        /// <param name="parameter">The parameter to convert.</param>
        /// <returns>The converted value.</returns>
        public static explicit operator long(OpenIdConnectParameter? parameter) => Convert<long>(parameter);

        /// <summary>
        /// Converts an <see cref="OpenIdConnectParameter"/> instance to a nullable long integer.
        /// </summary>
        /// <param name="parameter">The parameter to convert.</param>
        /// <returns>The converted value.</returns>
        public static explicit operator long?(OpenIdConnectParameter? parameter) => Convert<long?>(parameter);

        /// <summary>
        /// Converts an <see cref="OpenIdConnectParameter"/> instance to a string.
        /// </summary>
        /// <param name="parameter">The parameter to convert.</param>
        /// <returns>The converted value.</returns>
        public static explicit operator string(OpenIdConnectParameter? parameter) => Convert<string>(parameter);

        /// <summary>
        /// Converts an <see cref="OpenIdConnectParameter"/> instance to an array of strings.
        /// </summary>
        /// <param name="parameter">The parameter to convert.</param>
        /// <returns>The converted value.</returns>
        public static explicit operator string[](OpenIdConnectParameter? parameter) => Convert<string[]>(parameter);

        /// <summary>
        /// Converts a boolean to an <see cref="OpenIdConnectParameter"/> instance.
        /// </summary>
        /// <param name="value">The value to convert</param>
        /// <returns>An <see cref="OpenIdConnectParameter"/> instance.</returns>
        public static implicit operator OpenIdConnectParameter(bool value) => new OpenIdConnectParameter(value);

        /// <summary>
        /// Converts a nullable boolean to an <see cref="OpenIdConnectParameter"/> instance.
        /// </summary>
        /// <param name="value">The value to convert</param>
        /// <returns>An <see cref="OpenIdConnectParameter"/> instance.</returns>
        public static implicit operator OpenIdConnectParameter(bool? value) => new OpenIdConnectParameter(value);

        /// <summary>
        /// Converts a <see cref="JToken"/> to an <see cref="OpenIdConnectParameter"/> instance.
        /// </summary>
        /// <param name="value">The value to convert</param>
        /// <returns>An <see cref="OpenIdConnectParameter"/> instance.</returns>
        public static implicit operator OpenIdConnectParameter(JToken value) => new OpenIdConnectParameter(value);

        /// <summary>
        /// Converts a long integer to an <see cref="OpenIdConnectParameter"/> instance.
        /// </summary>
        /// <param name="value">The value to convert</param>
        /// <returns>An <see cref="OpenIdConnectParameter"/> instance.</returns>
        public static implicit operator OpenIdConnectParameter(long value) => new OpenIdConnectParameter(value);

        /// <summary>
        /// Converts a nullable long integer to an <see cref="OpenIdConnectParameter"/> instance.
        /// </summary>
        /// <param name="value">The value to convert</param>
        /// <returns>An <see cref="OpenIdConnectParameter"/> instance.</returns>
        public static implicit operator OpenIdConnectParameter(long? value) => new OpenIdConnectParameter(value);

        /// <summary>
        /// Converts a string to an <see cref="OpenIdConnectParameter"/> instance.
        /// </summary>
        /// <param name="value">The value to convert</param>
        /// <returns>An <see cref="OpenIdConnectParameter"/> instance.</returns>
        public static implicit operator OpenIdConnectParameter(string value) => new OpenIdConnectParameter(value);

        /// <summary>
        /// Converts an array of strings to an <see cref="OpenIdConnectParameter"/> instance.
        /// </summary>
        /// <param name="value">The value to convert</param>
        /// <returns>An <see cref="OpenIdConnectParameter"/> instance.</returns>
        public static implicit operator OpenIdConnectParameter(string[] value) => new OpenIdConnectParameter(value);

        /// <summary>
        /// Converts the parameter to the specified generic type.
        /// </summary>
        /// <typeparam name="T">The type the parameter will be converted to.</typeparam>
        /// <param name="parameter">The <see cref="OpenIdConnectParameter"/> instance.</param>
        /// <returns>The converted parameter.</returns>
        private static T Convert<T>(OpenIdConnectParameter? parameter)
        {
            try
            {
                switch (parameter?.Value)
                {
                    case null:
                        return default;

                    case T value:
                        return value;

                    case string value when typeof(T) == typeof(string[]):
                        return (T) (object) new string[] { value };

                    // Note: when the parameter is represented as a string, try to
                    // deserialize it if the requested type is a JArray or a JObject.
                    case string value when typeof(T) == typeof(JArray):
                        return (T) (object) JArray.Parse(value);

                    case string value when typeof(T) == typeof(JObject):
                        return (T) (object) JObject.Parse(value);

                    case string[] array:
                        return new JArray(array).ToObject<T>();

                    case JValue value when typeof(T) == typeof(string[]):
                        return (T) (object) new string[] { value.ToObject<string>() };

                    case JToken token:
                        return token.ToObject<T>();

                    case var value when typeof(T) == typeof(string[]):
                        return (T) (object) new string[] { new JValue(value).ToObject<string>() };

                    default:
                        return new JValue(parameter?.Value).ToObject<T>();
                }
            }

            // Swallow the conversion exceptions thrown by JSON.NET.
            catch (Exception exception) when (exception is ArgumentException ||
                                              exception is FormatException ||
                                              exception is InvalidCastException ||
                                              exception is JsonReaderException ||
                                              exception is JsonSerializationException)
            {
                return default;
            }

            // Other exceptions will be automatically re-thrown.
        }

        /// <summary>
        /// Determines whether an OpenID Connect parameter is null or empty.
        /// </summary>
        /// <param name="parameter">The OpenID Connect parameter.</param>
        /// <returns><c>true</c> if the parameter is null or empty, <c>false</c> otherwise.</returns>
        public static bool IsNullOrEmpty(OpenIdConnectParameter parameter)
        {
            switch (parameter.Value)
            {
                case null:
                    return true;

                case string value:
                    return string.IsNullOrEmpty(value);

                case string[] array:
                    return array.Length == 0;

                case JValue value when value.Value is string text:
                    return string.IsNullOrEmpty(text);

                case JArray array:
                    return !array.HasValues;

                case JToken token:
                    return !token.HasValues;

                default:
                    return false;
            }
        }
    }
}
