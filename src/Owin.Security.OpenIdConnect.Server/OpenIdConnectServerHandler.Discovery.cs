/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IdentityModel.Tokens;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Protocols;
using Microsoft.Owin.Security.Infrastructure;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Owin.Security.OpenIdConnect.Extensions;

namespace Owin.Security.OpenIdConnect.Server {
    internal partial class OpenIdConnectServerHandler : AuthenticationHandler<OpenIdConnectServerOptions> {
        private async Task<bool> InvokeConfigurationEndpointAsync() {
            // Metadata requests must be made via GET.
            // See http://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationRequest
            if (!string.Equals(Request.Method, "GET", StringComparison.OrdinalIgnoreCase)) {
                Options.Logger.LogError("The discovery request was rejected because an invalid " +
                                        "HTTP method was used: {Method}.", Request.Method);

                return await SendErrorPayloadAsync(new OpenIdConnectMessage {
                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = "Invalid HTTP method: make sure to use GET."
                });
            }

            var validatingContext = new ValidateConfigurationRequestContext(Context, Options);
            await Options.Provider.ValidateConfigurationRequest(validatingContext);

            // Stop processing the request if Validated was not called.
            if (!validatingContext.IsValidated) {
                Options.Logger.LogError("The configuration request was rejected.");

                return await SendErrorPayloadAsync(new OpenIdConnectMessage {
                    Error = validatingContext.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = validatingContext.ErrorDescription,
                    ErrorUri = validatingContext.ErrorUri
                });
            }

            var notification = new HandleConfigurationRequestContext(Context, Options);
            notification.Issuer = Context.GetIssuer(Options);

            if (Options.AuthorizationEndpointPath.HasValue) {
                notification.AuthorizationEndpoint = notification.Issuer.AddPath(Options.AuthorizationEndpointPath);
            }

            if (Options.CryptographyEndpointPath.HasValue) {
                notification.CryptographyEndpoint = notification.Issuer.AddPath(Options.CryptographyEndpointPath);
            }

            if (Options.UserinfoEndpointPath.HasValue) {
                notification.UserinfoEndpoint = notification.Issuer.AddPath(Options.UserinfoEndpointPath);
            }

            if (Options.IntrospectionEndpointPath.HasValue) {
                notification.IntrospectionEndpoint = notification.Issuer.AddPath(Options.IntrospectionEndpointPath);
            }

            if (Options.TokenEndpointPath.HasValue) {
                notification.TokenEndpoint = notification.Issuer.AddPath(Options.TokenEndpointPath);
            }

            if (Options.LogoutEndpointPath.HasValue) {
                notification.LogoutEndpoint = notification.Issuer.AddPath(Options.LogoutEndpointPath);
            }

            if (Options.AuthorizationEndpointPath.HasValue) {
                // Only expose the implicit grant type if the token
                // endpoint has not been explicitly disabled.
                notification.GrantTypes.Add(OpenIdConnectConstants.GrantTypes.Implicit);

                if (Options.TokenEndpointPath.HasValue) {
                    // Only expose the authorization code and refresh token grant types
                    // if both the authorization and the token endpoints are enabled.
                    notification.GrantTypes.Add(OpenIdConnectConstants.GrantTypes.AuthorizationCode);
                }
            }

            if (Options.TokenEndpointPath.HasValue) {
                notification.GrantTypes.Add(OpenIdConnectConstants.GrantTypes.RefreshToken);

                // If the authorization endpoint is disabled, assume the authorization server will
                // allow the client credentials and resource owner password credentials grant types.
                if (!Options.AuthorizationEndpointPath.HasValue) {
                    notification.GrantTypes.Add(OpenIdConnectConstants.GrantTypes.ClientCredentials);
                    notification.GrantTypes.Add(OpenIdConnectConstants.GrantTypes.Password);
                }
            }

            // Only populate response_modes_supported and response_types_supported
            // if the authorization endpoint is available.
            if (Options.AuthorizationEndpointPath.HasValue) {
                notification.ResponseModes.Add(OpenIdConnectConstants.ResponseModes.FormPost);
                notification.ResponseModes.Add(OpenIdConnectConstants.ResponseModes.Fragment);
                notification.ResponseModes.Add(OpenIdConnectConstants.ResponseModes.Query);

                notification.ResponseTypes.Add(OpenIdConnectConstants.ResponseTypes.Token);
                notification.ResponseTypes.Add(OpenIdConnectConstants.ResponseTypes.IdToken);

                notification.ResponseTypes.Add(
                    OpenIdConnectConstants.ResponseTypes.IdToken + ' ' +
                    OpenIdConnectConstants.ResponseTypes.Token);

                // Only expose response types containing code when
                // the token endpoint has not been explicitly disabled.
                if (Options.TokenEndpointPath.HasValue) {
                    notification.ResponseTypes.Add(OpenIdConnectConstants.ResponseTypes.Code);

                    notification.ResponseTypes.Add(
                        OpenIdConnectConstants.ResponseTypes.Code + ' ' +
                        OpenIdConnectConstants.ResponseTypes.Token);

                    notification.ResponseTypes.Add(
                        OpenIdConnectConstants.ResponseTypes.Code + ' ' +
                        OpenIdConnectConstants.ResponseTypes.IdToken);

                    notification.ResponseTypes.Add(
                        OpenIdConnectConstants.ResponseTypes.Code + ' ' +
                        OpenIdConnectConstants.ResponseTypes.IdToken + ' ' +
                        OpenIdConnectConstants.ResponseTypes.Token);
                }
            }

            notification.Scopes.Add(OpenIdConnectConstants.Scopes.OpenId);

            notification.SubjectTypes.Add(OpenIdConnectConstants.SubjectTypes.Public);

            notification.SigningAlgorithms.Add(OpenIdConnectConstants.Algorithms.RS256);

            await Options.Provider.HandleConfigurationRequest(notification);

            if (notification.HandledResponse) {
                return true;
            }

            else if (notification.Skipped) {
                return false;
            }
            
            var payload = new JObject();

            payload.Add(OpenIdConnectConstants.Metadata.Issuer, notification.Issuer);

            if (!string.IsNullOrEmpty(notification.AuthorizationEndpoint)) {
                payload.Add(OpenIdConnectConstants.Metadata.AuthorizationEndpoint, notification.AuthorizationEndpoint);
            }

            if (!string.IsNullOrEmpty(notification.UserinfoEndpoint)) {
                payload.Add(OpenIdConnectConstants.Metadata.UserinfoEndpoint, notification.UserinfoEndpoint);
            }

            if (!string.IsNullOrEmpty(notification.IntrospectionEndpoint)) {
                payload.Add(OpenIdConnectConstants.Metadata.IntrospectionEndpoint, notification.IntrospectionEndpoint);
            }

            if (!string.IsNullOrEmpty(notification.TokenEndpoint)) {
                payload.Add(OpenIdConnectConstants.Metadata.TokenEndpoint, notification.TokenEndpoint);
            }

            if (!string.IsNullOrEmpty(notification.LogoutEndpoint)) {
                payload.Add(OpenIdConnectConstants.Metadata.EndSessionEndpoint, notification.LogoutEndpoint);
            }

            if (!string.IsNullOrEmpty(notification.CryptographyEndpoint)) {
                payload.Add(OpenIdConnectConstants.Metadata.JwksUri, notification.CryptographyEndpoint);
            }

            payload.Add(OpenIdConnectConstants.Metadata.GrantTypesSupported,
                JArray.FromObject(notification.GrantTypes.Distinct()));

            payload.Add(OpenIdConnectConstants.Metadata.ResponseModesSupported,
                JArray.FromObject(notification.ResponseModes.Distinct()));

            payload.Add(OpenIdConnectConstants.Metadata.ResponseTypesSupported,
                JArray.FromObject(notification.ResponseTypes.Distinct()));

            payload.Add(OpenIdConnectConstants.Metadata.SubjectTypesSupported,
                JArray.FromObject(notification.SubjectTypes.Distinct()));

            payload.Add(OpenIdConnectConstants.Metadata.ScopesSupported,
                JArray.FromObject(notification.Scopes.Distinct()));

            payload.Add(OpenIdConnectConstants.Metadata.IdTokenSigningAlgValuesSupported,
                JArray.FromObject(notification.SigningAlgorithms.Distinct()));

            var context = new ApplyConfigurationResponseContext(Context, Options, payload);
            await Options.Provider.ApplyConfigurationResponse(context);

            if (context.HandledResponse) {
                return true;
            }

            else if (context.Skipped) {
                return false;
            }

            using (var buffer = new MemoryStream())
            using (var writer = new JsonTextWriter(new StreamWriter(buffer))) {
                payload.WriteTo(writer);
                writer.Flush();

                Response.ContentLength = buffer.Length;
                Response.ContentType = "application/json;charset=UTF-8";

                buffer.Seek(offset: 0, loc: SeekOrigin.Begin);
                await buffer.CopyToAsync(Response.Body, 4096, Request.CallCancelled);

                return true;
            }
        }

        private async Task<bool> InvokeCryptographyEndpointAsync() {
            // Metadata requests must be made via GET.
            // See http://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationRequest
            if (!string.Equals(Request.Method, "GET", StringComparison.OrdinalIgnoreCase)) {
                Options.Logger.LogError("The discovery request was rejected because an invalid " +
                                        "HTTP method was used: {Method}.", Request.Method);

                return await SendErrorPayloadAsync(new OpenIdConnectMessage {
                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = "Invalid HTTP method: make sure to use GET."
                });
            }

            var validatingContext = new ValidateCryptographyRequestContext(Context, Options);
            await Options.Provider.ValidateCryptographyRequest(validatingContext);

            // Stop processing the request if Validated was not called.
            if (!validatingContext.IsValidated) {
                Options.Logger.LogInformation("The discovery request was rejected by application code.");

                return await SendErrorPayloadAsync(new OpenIdConnectMessage {
                    Error = validatingContext.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = validatingContext.ErrorDescription,
                    ErrorUri = validatingContext.ErrorUri
                });
            }

            var notification = new HandleCryptographyRequestContext(Context, Options);

            foreach (var credentials in Options.EncryptingCredentials) {
                // Ignore the key if it's not supported.
                if (!credentials.SecurityKey.IsSupportedAlgorithm(SecurityAlgorithms.RsaOaepKeyWrap) &&
                    !credentials.SecurityKey.IsSupportedAlgorithm(SecurityAlgorithms.RsaV15KeyWrap)) {
                    Options.Logger.LogInformation("An unsupported encryption key was ignored and excluded " +
                                                  "from the key set: {Type}. Only asymmetric security keys " +
                                                  "supporting RSA1_5 or RSA-OAEP can be exposed via the JWKS " +
                                                  "endpoint.", credentials.SecurityKey.GetType().Name);

                    continue;
                }

                // Try to extract a key identifier from the credentials.
                LocalIdKeyIdentifierClause identifier = null;
                credentials.SecurityKeyIdentifier?.TryFind(out identifier);

                X509Certificate2 x509Certificate = null;

                // Determine whether the encrypting credentials are directly based on a X.509 certificate.
                var x509EncryptingCredentials = credentials as X509EncryptingCredentials;
                if (x509EncryptingCredentials != null) {
                    x509Certificate = x509EncryptingCredentials.Certificate;
                }

                // Skip looking for a X509SecurityKey in EncryptingCredentials.SecurityKey
                // if a certificate has been found in the EncryptingCredentials instance.
                if (x509Certificate == null) {
                    // Determine whether the security key is an asymmetric key embedded in a X.509 certificate.
                    var x509SecurityKey = credentials.SecurityKey as X509SecurityKey;
                    if (x509SecurityKey != null) {
                        x509Certificate = x509SecurityKey.Certificate;
                    }
                }

                // Skip looking for a X509AsymmetricSecurityKey in EncryptingCredentials.SecurityKey
                // if a certificate has been found in EncryptingCredentials or EncryptingCredentials.SecurityKey.
                if (x509Certificate == null) {
                    // Determine whether the security key is an asymmetric key embedded in a X.509 certificate.
                    var x509AsymmetricSecurityKey = credentials.SecurityKey as X509AsymmetricSecurityKey;
                    if (x509AsymmetricSecurityKey != null) {
                        // The X.509 certificate is not directly accessible when using X509AsymmetricSecurityKey.
                        // Reflection is the only way to get the certificate used to create the security key.
                        var field = typeof(X509AsymmetricSecurityKey).GetField(
                            name: "certificate",
                            bindingAttr: BindingFlags.Instance | BindingFlags.NonPublic);
                        Debug.Assert(field != null);

                        x509Certificate = (X509Certificate2) field.GetValue(x509AsymmetricSecurityKey);
                    }
                }

                if (x509Certificate != null) {
                    // Create a new JSON Web Key exposing the
                    // certificate instead of its public RSA key.
                    notification.Keys.Add(new JsonWebKey {
                        Use = JsonWebKeyUseNames.Enc,
                        Kty = JsonWebAlgorithmsKeyTypes.RSA,

                        // Resolve the JWA identifier from the algorithm specified in the credentials.
                        Alg = OpenIdConnectServerHelpers.GetJwtAlgorithm(credentials.Algorithm),

                        // Use the key identifier specified
                        // in the signing credentials.
                        Kid = identifier.LocalId,

                        // x5t must be base64url-encoded.
                        // See http://tools.ietf.org/html/draft-ietf-jose-json-web-key-31#section-4.8
                        X5t = Base64UrlEncoder.Encode(x509Certificate.GetCertHash()),

                        // Unlike E or N, the certificates contained in x5c
                        // must be base64-encoded and not base64url-encoded.
                        // See http://tools.ietf.org/html/draft-ietf-jose-json-web-key-31#section-4.7
                        X5c = { Convert.ToBase64String(x509Certificate.RawData) }
                    });
                }

                else {
                    var key = (AsymmetricSecurityKey) credentials.SecurityKey;

                    // Resolve the underlying algorithm from the security key.
                    var algorithm = (RSA) key.GetAsymmetricAlgorithm(
                        algorithm: SecurityAlgorithms.RsaOaepKeyWrap,
                        privateKey: false);
                    Debug.Assert(algorithm != null);

                    // Export the RSA public key to create a new JSON Web Key
                    // exposing the exponent and the modulus parameters.
                    var parameters = algorithm.ExportParameters(includePrivateParameters: false);

                    notification.Keys.Add(new JsonWebKey {
                        Use = JsonWebKeyUseNames.Enc,
                        Kty = JsonWebAlgorithmsKeyTypes.RSA,

                        // Resolve the JWA identifier from the algorithm specified in the credentials.
                        Alg = OpenIdConnectServerHelpers.GetJwtAlgorithm(credentials.Algorithm),

                        // Use the key identifier specified
                        // in the signing credentials.
                        Kid = identifier.LocalId,

                        // Both E and N must be base64url-encoded.
                        // See http://tools.ietf.org/html/draft-ietf-jose-json-web-key-31#appendix-A.1
                        E = Base64UrlEncoder.Encode(parameters.Exponent),
                        N = Base64UrlEncoder.Encode(parameters.Modulus)
                    });
                }
            }

            foreach (var credentials in Options.SigningCredentials) {
                // Ignore the key if it's not supported.
                if (!credentials.SigningKey.IsSupportedAlgorithm(SecurityAlgorithms.RsaSha256Signature)) {
                    Options.Logger.LogInformation("An unsupported signing key was ignored and excluded " +
                                                  "from the key set: {Type}. Only asymmetric security keys " +
                                                  "supporting RS256, RS384 or RS512 can be exposed " +
                                                  "via the JWKS endpoint.", credentials.SigningKey.GetType().Name);

                    continue;
                }

                // Try to extract a key identifier from the credentials.
                LocalIdKeyIdentifierClause identifier = null;
                credentials.SigningKeyIdentifier?.TryFind(out identifier);

                X509Certificate2 x509Certificate = null;

                // Determine whether the signing credentials are directly based on a X.509 certificate.
                var x509SigningCredentials = credentials as X509SigningCredentials;
                if (x509SigningCredentials != null) {
                    x509Certificate = x509SigningCredentials.Certificate;
                }

                // Skip looking for a X509SecurityKey in SigningCredentials.SigningKey
                // if a certificate has been found in the SigningCredentials instance.
                if (x509Certificate == null) {
                    // Determine whether the security key is an asymmetric key embedded in a X.509 certificate.
                    var x509SecurityKey = credentials.SigningKey as X509SecurityKey;
                    if (x509SecurityKey != null) {
                        x509Certificate = x509SecurityKey.Certificate;
                    }
                }

                // Skip looking for a X509AsymmetricSecurityKey in SigningCredentials.SigningKey
                // if a certificate has been found in SigningCredentials or SigningCredentials.SigningKey.
                if (x509Certificate == null) {
                    // Determine whether the security key is an asymmetric key embedded in a X.509 certificate.
                    var x509AsymmetricSecurityKey = credentials.SigningKey as X509AsymmetricSecurityKey;
                    if (x509AsymmetricSecurityKey != null) {
                        // The X.509 certificate is not directly accessible when using X509AsymmetricSecurityKey.
                        // Reflection is the only way to get the certificate used to create the security key.
                        var field = typeof(X509AsymmetricSecurityKey).GetField(
                            name: "certificate",
                            bindingAttr: BindingFlags.Instance | BindingFlags.NonPublic);
                        Debug.Assert(field != null);

                        x509Certificate = (X509Certificate2) field.GetValue(x509AsymmetricSecurityKey);
                    }
                }

                if (x509Certificate != null) {
                    // Create a new JSON Web Key exposing the
                    // certificate instead of its public RSA key.
                    notification.Keys.Add(new JsonWebKey {
                        Use = JsonWebKeyUseNames.Sig,
                        Kty = JsonWebAlgorithmsKeyTypes.RSA,

                        // Resolve the JWA identifier from the algorithm specified in the credentials.
                        Alg = OpenIdConnectServerHelpers.GetJwtAlgorithm(credentials.SignatureAlgorithm),

                        // Use the key identifier specified
                        // in the signing credentials.
                        Kid = identifier?.LocalId,

                        // x5t must be base64url-encoded.
                        // See http://tools.ietf.org/html/draft-ietf-jose-json-web-key-31#section-4.8
                        X5t = Base64UrlEncoder.Encode(x509Certificate.GetCertHash()),

                        // Unlike E or N, the certificates contained in x5c
                        // must be base64-encoded and not base64url-encoded.
                        // See http://tools.ietf.org/html/draft-ietf-jose-json-web-key-31#section-4.7
                        X5c = { Convert.ToBase64String(x509Certificate.RawData) }
                    });
                }

                else {
                    var key = (AsymmetricSecurityKey) credentials.SigningKey;

                    // Resolve the underlying algorithm from the security key.
                    var algorithm = (RSA) key.GetAsymmetricAlgorithm(
                        algorithm: SecurityAlgorithms.RsaOaepKeyWrap,
                        privateKey: false);
                    Debug.Assert(algorithm != null);

                    // Export the RSA public key to create a new JSON Web Key
                    // exposing the exponent and the modulus parameters.
                    var parameters = algorithm.ExportParameters(includePrivateParameters: false);

                    notification.Keys.Add(new JsonWebKey {
                        Use = JsonWebKeyUseNames.Sig,
                        Kty = JsonWebAlgorithmsKeyTypes.RSA,

                        // Resolve the JWA identifier from the algorithm specified in the credentials.
                        Alg = OpenIdConnectServerHelpers.GetJwtAlgorithm(credentials.SignatureAlgorithm),

                        // Use the key identifier specified
                        // in the signing credentials.
                        Kid = identifier?.LocalId,

                        // Both E and N must be base64url-encoded.
                        // See http://tools.ietf.org/html/draft-ietf-jose-json-web-key-31#appendix-A.1
                        E = Base64UrlEncoder.Encode(parameters.Exponent),
                        N = Base64UrlEncoder.Encode(parameters.Modulus)
                    });
                }
            }

            await Options.Provider.HandleCryptographyRequest(notification);

            if (notification.HandledResponse) {
                return true;
            }

            else if (notification.Skipped) {
                return false;
            }

            var payload = new JObject();
            var keys = new JArray();

            foreach (var key in notification.Keys) {
                var item = new JObject();

                // Ensure a key type has been provided.
                // See http://tools.ietf.org/html/draft-ietf-jose-json-web-key-31#section-4.1
                if (string.IsNullOrEmpty(key.Kty)) {
                    Options.Logger.LogError("A JSON Web Key was excluded from the key set because " +
                                            "it didn't contain the mandatory 'kid' parameter.");

                    continue;
                }

                // Create a dictionary associating the
                // JsonWebKey components with their values.
                var parameters = new Dictionary<string, string> {
                    { JsonWebKeyParameterNames.Kid, key.Kid },
                    { JsonWebKeyParameterNames.Use, key.Use },
                    { JsonWebKeyParameterNames.Kty, key.Kty },
                    { JsonWebKeyParameterNames.KeyOps, key.KeyOps },
                    { JsonWebKeyParameterNames.Alg, key.Alg },
                    { JsonWebKeyParameterNames.X5t, key.X5t },
                    { JsonWebKeyParameterNames.X5u, key.X5u },
                    { JsonWebKeyParameterNames.E, key.E },
                    { JsonWebKeyParameterNames.N, key.N }
                };

                foreach (var parameter in parameters) {
                    if (!string.IsNullOrEmpty(parameter.Value)) {
                        item.Add(parameter.Key, parameter.Value);
                    }
                }

                if (key.X5c.Any()) {
                    item.Add(JsonWebKeyParameterNames.X5c, JArray.FromObject(key.X5c));
                }

                keys.Add(item);
            }

            payload.Add(JsonWebKeyParameterNames.Keys, keys);

            var context = new ApplyCryptographyResponseContext(Context, Options, payload);
            await Options.Provider.ApplyCryptographyResponse(context);

            if (context.HandledResponse) {
                return true;
            }

            else if (context.Skipped) {
                return false;
            }

            using (var buffer = new MemoryStream())
            using (var writer = new JsonTextWriter(new StreamWriter(buffer))) {
                payload.WriteTo(writer);
                writer.Flush();

                Response.ContentLength = buffer.Length;
                Response.ContentType = "application/json;charset=UTF-8";

                buffer.Seek(offset: 0, loc: SeekOrigin.Begin);
                await buffer.CopyToAsync(Response.Body, 4096, Request.CallCancelled);

                return true;
            }
        }
    }
}
