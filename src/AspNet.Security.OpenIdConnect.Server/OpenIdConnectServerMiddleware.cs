/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/AspNet-OpenIdConnect-Server/Owin.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.IO;
using System.Linq;
using System.Security.Claims;
using Microsoft.AspNet.Authentication;
using Microsoft.AspNet.Authentication.DataHandler;
using Microsoft.AspNet.Authentication.DataHandler.Encoder;
using Microsoft.AspNet.Authentication.DataHandler.Serializer;
using Microsoft.AspNet.Builder;
using Microsoft.AspNet.DataProtection;
using Microsoft.Framework.Logging;
using Microsoft.Framework.OptionsModel;
using Microsoft.Framework.WebEncoders;

namespace AspNet.Security.OpenIdConnect.Server {
    /// <summary>
    /// Authorization Server middleware component which is added to an OWIN pipeline. This class is not
    /// created by application code directly, instead it is added by calling the the IAppBuilder UseOpenIdConnectServer 
    /// extension method.
    /// </summary>
    public class OpenIdConnectServerMiddleware : AuthenticationMiddleware<OpenIdConnectServerOptions> {
        private readonly ILogger logger;

        /// <summary>
        /// Authorization Server middleware component which is added to an OWIN pipeline. This constructor is not
        /// called by application code directly, instead it is added by calling the the IAppBuilder UseOpenIdConnectServer 
        /// extension method.
        /// </summary>
        public OpenIdConnectServerMiddleware(
            RequestDelegate next,
            IServiceProvider services,
            ILoggerFactory loggerFactory,
            IDataProtectionProvider dataProtectorProvider,
            IOptions<OpenIdConnectServerOptions> options,
            ConfigureOptions<OpenIdConnectServerOptions> configuration)
            : base(next, options, configuration) {
            _logger = loggerFactory.CreateLogger<OpenIdConnectServerMiddleware>();

            if (string.IsNullOrWhiteSpace(Options.AuthenticationScheme)) {
                throw new ArgumentNullException("options.AuthenticationScheme");
            }

            if (Options.Provider == null) {
                Options.Provider = new OpenIdConnectServerProvider();
            }

            if (Options.AuthorizationCodeFormat == null) {
                Options.AuthorizationCodeFormat = new EnhancedTicketDataFormat(
                    dataProtectorProvider.CreateProtector(
                        typeof(OpenIdConnectServerMiddleware).FullName,
                        Options.AuthenticationScheme, "Authentication_Code", "v1"));
            }

            if (Options.AccessTokenFormat == null) {
                Options.AccessTokenFormat = new EnhancedTicketDataFormat(
                    dataProtectorProvider.CreateProtector(
                        typeof(OpenIdConnectServerMiddleware).FullName,
                        Options.AuthenticationScheme, "Access_Token", "v1"));
            }

            if (Options.RefreshTokenFormat == null) {
                Options.RefreshTokenFormat = new EnhancedTicketDataFormat(
                    dataProtectorProvider.CreateProtector(
                        typeof(OpenIdConnectServerMiddleware).Namespace,
                        Options.AuthenticationScheme, "Refresh_Token", "v1"));
            }

            if (Options.HtmlEncoder == null) {
                Options.HtmlEncoder = services.GetHtmlEncoder();
            }

            if (Options.Cache == null) {
                throw new ArgumentNullException(nameof(Options.Cache));
            }

            if (Options.RandomNumberGenerator == null) {
                throw new ArgumentNullException(nameof(Options.RandomNumberGenerator));
            }

            if (Options.Provider == null) {
                throw new ArgumentNullException(nameof(Options.Provider));
            }

            if (Options.SystemClock == null) {
                throw new ArgumentNullException(nameof(Options.SystemClock));
            }
            
            if (string.IsNullOrWhiteSpace(Options.Issuer)) {
                throw new ArgumentNullException(nameof(Options.Issuer));
            }

            if (string.IsNullOrWhiteSpace(Options.AuthenticationScheme)) {
                throw new ArgumentException($"{nameof(Options.AuthenticationScheme)} cannot be null or empty", nameof(Options.AuthenticationScheme));
            }

            Uri issuer;
            if (!Uri.TryCreate(Options.Issuer, UriKind.Absolute, out issuer)) {
                throw new ArgumentException($"{nameof(Options.Issuer)} must be a valid absolute URI.", nameof(Options.Issuer));
            }

            // See http://openid.net/specs/openid-connect-discovery-1_0.html#IssuerDiscovery
            if (!string.IsNullOrWhiteSpace(issuer.Query) || !string.IsNullOrWhiteSpace(issuer.Fragment)) {
                throw new ArgumentException($"{nameof(Options.Issuer)} must contain no query and no fragment.", nameof(Options.Issuer));
            }

            // Note: while the issuer parameter should be a HTTPS URI, making HTTPS mandatory
            // in AspNet.Security.OpenIdConnect.Server would prevent the end developer from
            // running the different samples in test environments, where HTTPS is often disabled.
            // To mitigate this issue, AllowInsecureHttp can be set to true to bypass the HTTPS check.
            // See http://openid.net/specs/openid-connect-discovery-1_0.html#IssuerDiscovery
            if (!Options.AllowInsecureHttp && string.Equals(issuer.Scheme, "http", StringComparison.OrdinalIgnoreCase)) {
                throw new ArgumentException(
                    $"{nameof(Options.Issuer)} must be a HTTPS URI when " +
                    $"{nameof(Options.AllowInsecureHttp)} is not set to true.", nameof(Options.Issuer));
            }

            if (Options.Issuer.EndsWith("/")) {
                // Remove the trailing slash to make concatenation easier in
                // OpenIdConnectServerHandler.InvokeConfigurationEndpointAsync.
                Options.Issuer = Options.Issuer.Substring(0, Options.Issuer.Length - 1);
            }
        }

        /// <summary>
        /// Called by the AuthenticationMiddleware base class to create a per-request handler. 
        /// </summary>
        /// <returns>A new instance of the request handler</returns>
        protected override AuthenticationHandler<OpenIdConnectServerOptions> CreateHandler() {
            return new OpenIdConnectServerHandler(logger);
        }

        // Remove when the built-in ticket serializer supports Claim.Properties.
        // See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server/issues/71
        private sealed class EnhancedTicketSerializer : IDataSerializer<AuthenticationTicket> {
            private const int FormatVersion = 3;

            public byte[] Serialize(AuthenticationTicket model) {
                using (var memory = new MemoryStream()) {
                    using (var writer = new BinaryWriter(memory)) {
                        Write(writer, model);
                    }
                    return memory.ToArray();
                }
            }

            public AuthenticationTicket Deserialize(byte[] data) {
                using (var memory = new MemoryStream(data)) {
                    using (var reader = new BinaryReader(memory)) {
                        return Read(reader);
                    }
                }
            }

            public static void Write(BinaryWriter writer, AuthenticationTicket model) {
                writer.Write(FormatVersion);
                writer.Write(model.AuthenticationScheme);
                var principal = model.Principal;
                writer.Write(principal.Identities.Count());
                foreach (var identity in principal.Identities) {
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
                }
                PropertiesSerializer.Write(writer, model.Properties);
            }

            public static AuthenticationTicket Read(BinaryReader reader) {
                if (reader.ReadInt32() != FormatVersion) {
                    return null;
                }
                string authenticationScheme = reader.ReadString();
                int identityCount = reader.ReadInt32();
                var identities = new ClaimsIdentity[identityCount];
                for (int i = 0; i != identityCount; ++i) {
                    string authenticationType = reader.ReadString();
                    string nameClaimType = ReadWithDefault(reader, DefaultValues.NameClaimType);
                    string roleClaimType = ReadWithDefault(reader, DefaultValues.RoleClaimType);
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
                    identities[i] = new ClaimsIdentity(claims, authenticationType, nameClaimType, roleClaimType);
                }
                var properties = PropertiesSerializer.Read(reader);
                return new AuthenticationTicket(new ClaimsPrincipal(identities), properties, authenticationScheme);
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
