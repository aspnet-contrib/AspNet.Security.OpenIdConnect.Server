/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/AspNet-OpenIdConnect-Server/Owin.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.IO;
using System.Linq;
using System.Security.Claims;
using Microsoft.Owin;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.DataHandler;
using Microsoft.Owin.Security.DataHandler.Encoder;
using Microsoft.Owin.Security.DataHandler.Serializer;
using Microsoft.Owin.Security.DataProtection;
using Microsoft.Owin.Security.Infrastructure;

namespace Owin.Security.OpenIdConnect.Server {
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
            OwinMiddleware next,
            IAppBuilder app,
            OpenIdConnectServerOptions options)
            : base(next, options) {
            logger = app.CreateLogger<OpenIdConnectServerMiddleware>();
            
            if (Options.AuthorizationCodeFormat == null) {
                Options.AuthorizationCodeFormat = new EnhancedTicketDataFormat(
                    app.CreateDataProtector(
                        typeof(OpenIdConnectServerMiddleware).FullName,
                        "Authentication_Code", "v1"));
            }

            if (Options.AccessTokenFormat == null) {
                Options.AccessTokenFormat = new TicketDataFormat(
                    app.CreateDataProtector(
                        "Microsoft.Owin.Security.OAuth",
                        "Access_Token", "v1"));
            }

            if (Options.RefreshTokenFormat == null) {
                Options.RefreshTokenFormat = new EnhancedTicketDataFormat(
                    app.CreateDataProtector(
                        typeof(OpenIdConnectServerMiddleware).Namespace,
                        "Refresh_Token", "v1"));
            }

            if (Options.RandomNumberGenerator == null) {
                throw new ArgumentNullException("options.RandomNumberGenerator");
            }

            if (Options.Provider == null) {
                throw new ArgumentNullException("options.Provider");
            }
            
            if (Options.SystemClock == null) {
                throw new ArgumentNullException("options.SystemClock");
            }

            if (!Options.AuthorizationEndpointPath.HasValue) {
                throw new ArgumentException("options.AuthorizationEndpointPath must be provided. " +
                    "Make sure to use a custom value or remove the setter call to use the default value.",
                    "options.AuthorizationEndpointPath");
            }

            if (string.IsNullOrWhiteSpace(Options.Issuer)) {
                throw new ArgumentNullException("options.Issuer");
            }

            Uri issuer;
            if (!Uri.TryCreate(Options.Issuer, UriKind.Absolute, out issuer)) {
                throw new ArgumentException("options.Issuer must be a valid absolute URI.", "options.Issuer");
            }

            // See http://openid.net/specs/openid-connect-discovery-1_0.html#IssuerDiscovery
            if (!string.IsNullOrWhiteSpace(issuer.Query) || !string.IsNullOrWhiteSpace(issuer.Fragment)) {
                throw new ArgumentException("options.Issuer must contain no query and no fragment parts.", "options.Issuer");
            }

            // Note: while the issuer parameter should be a HTTPS URI, making HTTPS mandatory
            // in Owin.Security.OpenIdConnect.Server would prevent the end developer from
            // running the different samples in test environments, where HTTPS is often disabled.
            // To mitigate this issue, AllowInsecureHttp can be set to true to bypass the HTTPS check.
            // See http://openid.net/specs/openid-connect-discovery-1_0.html#IssuerDiscovery
            if (!Options.AllowInsecureHttp && string.Equals(issuer.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase)) {
                throw new ArgumentException("options.Issuer must be a HTTPS URI when " +
                    "options.AllowInsecureHttp is not set to true.", "options.Issuer");
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
                if (writer == null) {
                    throw new ArgumentNullException("writer");
                }

                if (model == null) {
                    throw new ArgumentNullException("model");
                }

                writer.Write(FormatVersion);
                ClaimsIdentity identity = model.Identity;
                writer.Write(identity.AuthenticationType);
                WriteWithDefault(writer, identity.NameClaimType, DefaultValues.NameClaimType);
                WriteWithDefault(writer, identity.RoleClaimType, DefaultValues.RoleClaimType);
                writer.Write(identity.Claims.Count());

                foreach (var claim in identity.Claims) {
                    WriteClaim(writer, claim, identity.NameClaimType);
                }

                BootstrapContext bc = identity.BootstrapContext as BootstrapContext;
                if (bc == null || string.IsNullOrWhiteSpace(bc.Token)) {
                    writer.Write(0);
                }

                else {
                    writer.Write(bc.Token.Length);
                    writer.Write(bc.Token);
                }

                PropertiesSerializer.Write(writer, model.Properties);
            }

            public static AuthenticationTicket Read(BinaryReader reader) {
                if (reader == null) {
                    throw new ArgumentNullException("reader");
                }

                if (reader.ReadInt32() != FormatVersion) {
                    return null;
                }

                string authenticationType = reader.ReadString();
                string nameClaimType = ReadWithDefault(reader, DefaultValues.NameClaimType);
                string roleClaimType = ReadWithDefault(reader, DefaultValues.RoleClaimType);
                int count = reader.ReadInt32();

                var claims = new Claim[count];

                for (int index = 0; index != count; ++index) {
                    claims[index] = ReadClaim(reader, nameClaimType);
                }

                var identity = new ClaimsIdentity(claims, authenticationType, nameClaimType, roleClaimType);

                int bootstrapContextSize = reader.ReadInt32();
                if (bootstrapContextSize > 0) {
                    identity.BootstrapContext = new BootstrapContext(reader.ReadString());
                }

                AuthenticationProperties properties = PropertiesSerializer.Read(reader);
                return new AuthenticationTicket(identity, properties);
            }

            private static void WriteClaim(BinaryWriter writer, Claim claim, string nameClaimType) {
                WriteWithDefault(writer, claim.Type, nameClaimType);
                writer.Write(claim.Value);
                WriteWithDefault(writer, claim.ValueType, DefaultValues.StringValueType);
                WriteWithDefault(writer, claim.Issuer, DefaultValues.LocalAuthority);
                WriteWithDefault(writer, claim.OriginalIssuer, claim.Issuer);
                writer.Write(claim.Properties.Count);

                foreach (KeyValuePair<string, string> property in claim.Properties) {
                    writer.Write(property.Key);
                    writer.Write(property.Value);
                }
            }

            private static Claim ReadClaim(BinaryReader reader, string nameClaimType) {
                string type = ReadWithDefault(reader, nameClaimType);
                string value = reader.ReadString();
                string valueType = ReadWithDefault(reader, DefaultValues.StringValueType);
                string issuer = ReadWithDefault(reader, DefaultValues.LocalAuthority);
                string originalIssuer = ReadWithDefault(reader, issuer);
                int count = reader.ReadInt32();

                var claim = new Claim(type, value, valueType, issuer, originalIssuer);

                for (int index = 0; index != count; ++index) {
                    claim.Properties.Add(key: reader.ReadString(), value: reader.ReadString());
                }

                return claim;
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
