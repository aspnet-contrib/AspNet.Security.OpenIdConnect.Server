/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.IdentityModel.Tokens;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.AspNet.Authentication;
using Microsoft.AspNet.Authentication.DataHandler;
using Microsoft.AspNet.Authentication.DataHandler.Encoder;
using Microsoft.AspNet.Authentication.DataHandler.Serializer;
using Microsoft.AspNet.Builder;
using Microsoft.AspNet.DataProtection;
using Microsoft.AspNet.Http;
using Microsoft.AspNet.Http.Authentication;
using Microsoft.Framework.DependencyInjection;
using Microsoft.Framework.OptionsModel;
using Microsoft.IdentityModel.Protocols;

namespace AspNet.Security.OpenIdConnect.Server {
    /// <summary>
    /// Provides extension methods allowing to easily register an
    /// ASP.NET-powered OpenID Connect server and to retrieve various
    /// OpenID Connect-related contexts from the ASP.NET environment.
    /// </summary>
    public static class OpenIdConnectServerExtensions {
        /// <summary>
        /// Configures the settings used by the OpenID Connect server.
        /// </summary>
        /// <param name="services">The services collection.</param>
        /// <returns>The services collection.</returns>
        public static IServiceCollection ConfigureOpenIdConnectServer(this IServiceCollection services, Action<OpenIdConnectServerOptions> options) {
            if (services == null) {
                throw new ArgumentNullException(nameof(services));
            }

            if (options == null) {
                throw new ArgumentNullException(nameof(options));
            }

            return services.Configure(options);
        }

        /// <summary>
        /// Adds a specs-compliant OpenID Connect server in the ASP.NET pipeline.
        /// </summary>
        /// <param name="app">The web application builder.</param>
        /// <returns>The application builder.</returns>
        public static IApplicationBuilder UseOpenIdConnectServer(this IApplicationBuilder app) {
            if (app == null) {
                throw new ArgumentNullException(nameof(app));
            }

            return app.UseOpenIdConnectServer(options => { });
        }

        /// <summary>
        /// Adds a specs-compliant OpenID Connect server in the ASP.NET pipeline.
        /// </summary>
        /// <param name="app">The web application builder.</param>
        /// <param name="options">Options which control the behavior of the OpenID Connect server.</param>
        /// <returns>The application builder.</returns>
        public static IApplicationBuilder UseOpenIdConnectServer(this IApplicationBuilder app, Action<OpenIdConnectServerOptions> options) {
            if (app == null) {
                throw new ArgumentNullException(nameof(app));
            }

            if (options == null) {
                throw new ArgumentNullException(nameof(options));
            }

            return app.UseMiddleware<OpenIdConnectServerMiddleware>(new ConfigureOptions<OpenIdConnectServerOptions>(options));
        }

        /// <summary>
        /// Retrieves the <see cref="OpenIdConnectMessage"/> instance
        /// associated with the current request from the ASP.NET context.
        /// </summary>
        /// <param name="notification">The ASP.NET context.</param>
        /// <returns>The <see cref="OpenIdConnectMessage"/> associated with the current request.</returns>
        public static OpenIdConnectMessage GetOpenIdConnectRequest(this HttpContext context) {
            if (context == null) {
                throw new ArgumentNullException(nameof(context));
            }

            return GetFeature(context).Request;
        }

        /// <summary>
        /// Inserts the ambient <see cref="OpenIdConnectMessage"/> request in the ASP.NET context.
        /// </summary>
        /// <param name="notification">The ASP.NET context.</param>
        /// <param name="request">The ambient <see cref="OpenIdConnectMessage"/>.</param>
        public static void SetOpenIdConnectRequest(this HttpContext context, OpenIdConnectMessage request) {
            if (context == null) {
                throw new ArgumentNullException(nameof(context));
            }

            GetFeature(context).Request = request;
        }

        /// <summary>
        /// Retrieves the <see cref="OpenIdConnectMessage"/> instance
        /// associated with the current response from the ASP.NET context.
        /// </summary>
        /// <param name="notification">The ASP.NET context.</param>
        /// <returns>The <see cref="OpenIdConnectMessage"/> associated with the current response.</returns>
        public static OpenIdConnectMessage GetOpenIdConnectResponse(this HttpContext context) {
            if (context == null) {
                throw new ArgumentNullException(nameof(context));
            }

            return GetFeature(context).Response;
        }

        /// <summary>
        /// Inserts the ambient <see cref="OpenIdConnectMessage"/> response in the ASP.NET context.
        /// </summary>
        /// <param name="notification">The ASP.NET context.</param>
        /// <param name="response">The ambient <see cref="OpenIdConnectMessage"/>.</param>
        public static void SetOpenIdConnectResponse(this HttpContext context, OpenIdConnectMessage response) {
            if (context == null) {
                throw new ArgumentNullException(nameof(context));
            }

            GetFeature(context).Response = response;
        }

        /// <summary>
        /// Retrieves the <see cref="OpenIdConnectMessage"/> request from the given session.
        /// </summary>
        /// <param name="session">The ASP.NET session which the request must be retrieved from.</param>
        /// <param name="key">The unique identifier used to retrieve the request from the session.</param>
        /// <returns>The <see cref="OpenIdConnectMessage"/> stored in the session or <c>null</c> if it cannot be found.</returns>
        public static OpenIdConnectMessage GetOpenIdConnectRequest(this ISessionCollection session, string key) {
            if (session == null) {
                throw new ArgumentNullException(nameof(session));
            }

            var buffer = session.Get(key);
            if (buffer == null) {
                return null;
            }

            using (var stream = new MemoryStream(buffer))
            using (var reader = new BinaryReader(stream)) {
                var version = reader.ReadInt32();
                if (version != 1) {
                    session.Remove(key);

                    return null;
                }

                var request = new OpenIdConnectMessage();
                var length = reader.ReadInt32();

                for (var index = 0; index < length; index++) {
                    var name = reader.ReadString();
                    var value = reader.ReadString();

                    request.SetParameter(name, value);
                }

                return request;
            }
        }

        /// <summary>
        /// Inserts the <see cref="OpenIdConnectMessage"/> request in the given session.
        /// </summary>
        /// <param name="session">The ASP.NET session which the request must be added to.</param>
        /// <param name="key">The unique identifier used to store the request in the session.</param>
        /// <param name="request">The <see cref="OpenIdConnectMessage"/> to store.</param>
        public static void SetOpenIdConnectRequest(this ISessionCollection session, string key, OpenIdConnectMessage request) {
            if (session == null) {
                throw new ArgumentNullException(nameof(session));
            }

            if (request == null) {
                session.Remove(key);

                return;
            }
            
            using (var stream = new MemoryStream())
            using (var writer = new BinaryWriter(stream)) {
                writer.Write(/* version: */ 1);
                writer.Write(request.Parameters.Count);

                foreach (var parameter in request.Parameters) {
                    writer.Write(parameter.Key);
                    writer.Write(parameter.Value);
                }

                session.Set(key, stream.ToArray());
            }
        }

        /// <summary>
        /// Creates a new enhanced ticket format that supports serializing
        /// <see cref="ClaimsIdentity.Actor"/> and <see cref="Claim.Properties"/>.
        /// </summary>
        /// <param name="provider">The data protector provider</param>
        /// <param name="purposes">The unique values used to initialize the data protector.</param>
        public static ISecureDataFormat<AuthenticationTicket> CreateTicketFormat(this IDataProtectionProvider provider, params string[] purposes) {
            if (provider == null) {
                throw new ArgumentNullException(nameof(provider));
            }

            return new EnhancedTicketDataFormat(provider.CreateProtector(purposes));
        }

        private static IOpenIdConnectServerFeature GetFeature(HttpContext context) {
            var feature = context.GetFeature<IOpenIdConnectServerFeature>();
            if (feature == null) {
                feature = new OpenIdConnectServerFeature();

                context.SetFeature(feature);
            }

            return feature;
        }

        internal static bool IsSupportedAlgorithm(this SecurityKey securityKey, string algorithm) {
            var x509SecurityKey = securityKey as X509SecurityKey;
            if (x509SecurityKey == null) {
                return false;
            }

            var rsaPrivateKey = x509SecurityKey.PrivateKey as RSACryptoServiceProvider;
            if (rsaPrivateKey == null) {
                return false;
            }

            return true;
        }

        internal static AuthenticationProperties Copy(this AuthenticationProperties properties) {
            return new AuthenticationProperties(properties.Items.ToDictionary(pair => pair.Key, pair => pair.Value));
        }

        internal static string GetAudience(this AuthenticationProperties properties) {
            if (properties == null) {
                return null;
            }

            string audience;
            if (!properties.Items.TryGetValue("audience", out audience)) {
                return null;
            }

            return audience;
        }

        // Remove when the built-in ticket serializer supports Claim.Properties.
        // See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server/issues/71
        private sealed class EnhancedTicketSerializer : IDataSerializer<AuthenticationTicket> {
            private const int FormatVersion = 3;

            public byte[] Serialize(AuthenticationTicket model) {
                using (var memory = new MemoryStream())
                using (var writer = new BinaryWriter(memory)) {
                    writer.Write(FormatVersion);

                    writer.Write(model.AuthenticationScheme);
                    writer.Write(model.Principal.Identities.Count());

                    foreach (var identity in model.Principal.Identities) {
                        WriteIdentity(writer, identity);
                    }

                    PropertiesSerializer.Write(writer, model.Properties);

                    return memory.ToArray();
                }
            }

            public AuthenticationTicket Deserialize(byte[] data) {
                using (var memory = new MemoryStream(data))
                using (var reader = new BinaryReader(memory)) {
                    if (reader.ReadInt32() != FormatVersion) {
                        return null;
                    }

                    var scheme = reader.ReadString();

                    var identities = new ClaimsIdentity[reader.ReadInt32()];
                    for (int index = 0; index != identities.Length; ++index) {
                        identities[index] = ReadIdentity(reader);
                    }
                    
                    var properties = PropertiesSerializer.Read(reader);

                    return new AuthenticationTicket(new ClaimsPrincipal(identities), properties, scheme);
                }
            }

            private static void WriteIdentity(BinaryWriter writer, ClaimsIdentity identity) {
                var authenticationType = string.IsNullOrWhiteSpace(identity.AuthenticationType) ? string.Empty : identity.AuthenticationType;

                writer.Write(authenticationType);
                WriteWithDefault(writer, identity.NameClaimType, DefaultValues.NameClaimType);
                WriteWithDefault(writer, identity.RoleClaimType, DefaultValues.RoleClaimType);
                writer.Write(identity.Claims.Count());

                foreach (var claim in identity.Claims) {
                    WriteWithDefault(writer, claim.Type, identity.NameClaimType);
                    writer.Write(claim.Value);
                    WriteWithDefault(writer, claim.ValueType, DefaultValues.StringValueType);
                    WriteWithDefault(writer, claim.Issuer, DefaultValues.LocalAuthority);
                    WriteWithDefault(writer, claim.OriginalIssuer, claim.Issuer);

                    writer.Write(claim.Properties.Count);

                    foreach (var property in claim.Properties) {
                        writer.Write(property.Key);
                        writer.Write(property.Value);
                    }
                }

                if (identity.Actor != null) {
                    writer.Write(true);
                    WriteIdentity(writer, identity.Actor);
                }

                else {
                    writer.Write(false);
                }
            }

            private static ClaimsIdentity ReadIdentity(BinaryReader reader) {
                var authenticationType = reader.ReadString();
                var nameClaimType = ReadWithDefault(reader, DefaultValues.NameClaimType);
                var roleClaimType = ReadWithDefault(reader, DefaultValues.RoleClaimType);
                int count = reader.ReadInt32();
                var claims = new Claim[count];

                for (int index = 0; index != count; ++index) {
                    string type = ReadWithDefault(reader, nameClaimType);
                    string value = reader.ReadString();
                    string valueType = ReadWithDefault(reader, DefaultValues.StringValueType);
                    string issuer = ReadWithDefault(reader, DefaultValues.LocalAuthority);
                    string originalIssuer = ReadWithDefault(reader, issuer);

                    claims[index] = new Claim(type, value, valueType, issuer, originalIssuer);

                    var x = reader.ReadInt32();

                    for (int j = 0; j != x; ++j) {
                        claims[index].Properties.Add(key: reader.ReadString(), value: reader.ReadString());
                    }
                }

                var identity = new ClaimsIdentity(claims, authenticationType, nameClaimType, roleClaimType);

                if (reader.ReadBoolean()) {
                    identity.Actor = ReadIdentity(reader);
                }

                return identity;
            }

            private static void WriteWithDefault(BinaryWriter writer, string value, string defaultValue) {
                if (string.Equals(value, defaultValue, StringComparison.Ordinal)) {
                    writer.Write(DefaultValues.DefaultStringPlaceholder);
                }
                else {
                    writer.Write(value);
                }
            }

            private static string ReadWithDefault(BinaryReader reader, string defaultValue) {
                string value = reader.ReadString();
                if (string.Equals(value, DefaultValues.DefaultStringPlaceholder, StringComparison.Ordinal)) {
                    return defaultValue;
                }
                return value;
            }

            private static class DefaultValues {
                public const string DefaultStringPlaceholder = "\0";
                public const string NameClaimType = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name";
                public const string RoleClaimType = "http://schemas.microsoft.com/ws/2008/06/identity/claims/role";
                public const string LocalAuthority = "LOCAL AUTHORITY";
                public const string StringValueType = "http://www.w3.org/2001/XMLSchema#string";
            }
        }

        private sealed class EnhancedTicketDataFormat : SecureDataFormat<AuthenticationTicket> {
            private static readonly EnhancedTicketSerializer Serializer = new EnhancedTicketSerializer();

            public EnhancedTicketDataFormat(IDataProtector protector)
                : base(Serializer, protector, TextEncodings.Base64Url) {
            }
        }
    }
}
