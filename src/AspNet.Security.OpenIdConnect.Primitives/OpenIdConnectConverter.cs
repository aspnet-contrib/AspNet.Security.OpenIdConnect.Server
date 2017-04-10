/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.Reflection;
using JetBrains.Annotations;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace AspNet.Security.OpenIdConnect.Primitives
{
    /// <summary>
    /// Represents a JSON.NET converter able to convert <see cref="OpenIdConnectRequest"/>
    /// and <see cref="OpenIdConnectResponse"/> instances.
    /// </summary>
    public class OpenIdConnectConverter : JsonConverter
    {
        /// <summary>
        /// Determines whether the specified type is supported by this converter.
        /// </summary>
        /// <param name="type">The type to convert.</param>
        /// <returns><c>true</c> if the type is supported, <c>false</c> otherwise.</returns>
        public override bool CanConvert([NotNull] Type type)
        {
            if (type == null)
            {
                throw new ArgumentNullException(nameof(type));
            }

            return typeof(OpenIdConnectMessage).GetTypeInfo().IsAssignableFrom(type.GetTypeInfo());
        }

        /// <summary>
        /// Deserializes an <see cref="OpenIdConnectMessage"/> instance.
        /// </summary>
        /// <param name="reader">The JSON reader.</param>
        /// <param name="type">The type of the deserialized instance.</param>
        /// <param name="value">The existing <see cref="OpenIdConnectMessage"/>, if applicable.</param>
        /// <param name="serializer">The JSON serializer.</param>
        /// <returns>The deserialized <see cref="OpenIdConnectMessage"/> instance.</returns>
        public override object ReadJson(
            [NotNull] JsonReader reader, [NotNull] Type type,
            [CanBeNull] object value, [CanBeNull] JsonSerializer serializer)
        {
            if (reader == null)
            {
                throw new ArgumentNullException(nameof(reader));
            }

            if (type == null)
            {
                throw new ArgumentNullException(nameof(type));
            }

            // Note: OpenID Connect messages are always represented as JSON objects.
            var payload = JToken.Load(reader) as JObject;
            if (payload == null)
            {
                throw new JsonSerializationException("An error occurred while reading the JSON payload.");
            }

            // If no existing value was specified, instantiate a
            // new request/response depending on the requested type.
            var message = value as OpenIdConnectMessage;
            if (message == null)
            {
                if (type == typeof(OpenIdConnectMessage))
                {
                    message = new OpenIdConnectMessage();
                }

                else if (type == typeof(OpenIdConnectRequest))
                {
                    message = new OpenIdConnectRequest();
                }

                else if (type == typeof(OpenIdConnectResponse))
                {
                    message = new OpenIdConnectResponse();
                }
            }

            if (message == null)
            {
                throw new ArgumentException("The specified type is not supported.", nameof(type));
            }

            foreach (var parameter in payload.Properties())
            {
                message.AddParameter(parameter.Name, parameter.Value);
            }

            return message;
        }

        /// <summary>
        /// Serializes an <see cref="OpenIdConnectMessage"/>.
        /// </summary>
        /// <param name="writer">The JSON writer.</param>
        /// <param name="value">The <see cref="OpenIdConnectMessage"/> instance.</param>
        /// <param name="serializer">The JSON serializer.</param>
        public override void WriteJson([NotNull] JsonWriter writer,
            [NotNull] object value, [CanBeNull] JsonSerializer serializer)
        {
            if (writer == null)
            {
                throw new ArgumentNullException(nameof(writer));
            }

            if (value == null)
            {
                throw new ArgumentNullException(nameof(value));
            }

            var message = value as OpenIdConnectMessage;
            if (message == null)
            {
                throw new ArgumentException("The specified object is not supported.", nameof(value));
            }

            writer.WriteStartObject();

            foreach (var parameter in message.GetParameters())
            {
                writer.WritePropertyName(parameter.Key);

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
    }
}
