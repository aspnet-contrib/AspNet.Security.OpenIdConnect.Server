/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Extensions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json.Linq;

namespace AspNet.Security.OpenIdConnect.Server {
    internal partial class OpenIdConnectServerHandler : AuthenticationHandler<OpenIdConnectServerOptions> {
        private async Task<bool> InvokeConfigurationEndpointAsync() {
            // Metadata requests must be made via GET.
            // See http://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationRequest
            if (!string.Equals(Request.Method, "GET", StringComparison.OrdinalIgnoreCase)) {
                Logger.LogError("The discovery request was rejected because an invalid " +
                                "HTTP method was used: {Method}.", Request.Method);

                return await SendConfigurationResponseAsync(null, new OpenIdConnectMessage {
                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = "Invalid HTTP method: make sure to use GET."
                });
            }

            var request = new OpenIdConnectMessage(Request.Query.ToDictionary());

            var context = new ValidateConfigurationRequestContext(Context, Options);
            await Options.Provider.ValidateConfigurationRequest(context);

            if (!context.IsValidated) {
                Logger.LogError("The discovery request was rejected with the following error: {Error} ; {Description}",
                                /* Error: */ context.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
                                /* Description: */ context.ErrorDescription);

                return await SendConfigurationResponseAsync(request, new OpenIdConnectMessage {
                    Error = context.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = context.ErrorDescription,
                    ErrorUri = context.ErrorUri
                });
            }

            var notification = new HandleConfigurationRequestContext(Context, Options, request);
            notification.Issuer = Context.GetIssuer(Options);

            if (Options.AuthorizationEndpointPath.HasValue) {
                notification.AuthorizationEndpoint = notification.Issuer.AddPath(Options.AuthorizationEndpointPath);
            }

            if (Options.CryptographyEndpointPath.HasValue) {
                notification.CryptographyEndpoint = notification.Issuer.AddPath(Options.CryptographyEndpointPath);
            }

            if (Options.IntrospectionEndpointPath.HasValue) {
                notification.IntrospectionEndpoint = notification.Issuer.AddPath(Options.IntrospectionEndpointPath);
            }

            if (Options.LogoutEndpointPath.HasValue) {
                notification.LogoutEndpoint = notification.Issuer.AddPath(Options.LogoutEndpointPath);
            }

            if (Options.RevocationEndpointPath.HasValue) {
                notification.RevocationEndpoint = notification.Issuer.AddPath(Options.RevocationEndpointPath);
            }

            if (Options.TokenEndpointPath.HasValue) {
                notification.TokenEndpoint = notification.Issuer.AddPath(Options.TokenEndpointPath);
            }

            if (Options.UserinfoEndpointPath.HasValue) {
                notification.UserinfoEndpoint = notification.Issuer.AddPath(Options.UserinfoEndpointPath);
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

            notification.SigningAlgorithms.Add(OpenIdConnectConstants.Algorithms.RsaSha256);

            await Options.Provider.HandleConfigurationRequest(notification);

            if (notification.HandledResponse) {
                return true;
            }

            else if (notification.Skipped) {
                return false;
            }

            var response = new JObject();

            response.Add(OpenIdConnectConstants.Metadata.Issuer, notification.Issuer);

            if (!string.IsNullOrEmpty(notification.AuthorizationEndpoint)) {
                response.Add(OpenIdConnectConstants.Metadata.AuthorizationEndpoint, notification.AuthorizationEndpoint);
            }

            if (!string.IsNullOrEmpty(notification.CryptographyEndpoint)) {
                response.Add(OpenIdConnectConstants.Metadata.JwksUri, notification.CryptographyEndpoint);
            }

            if (!string.IsNullOrEmpty(notification.IntrospectionEndpoint)) {
                response.Add(OpenIdConnectConstants.Metadata.IntrospectionEndpoint, notification.IntrospectionEndpoint);
            }

            if (!string.IsNullOrEmpty(notification.LogoutEndpoint)) {
                response.Add(OpenIdConnectConstants.Metadata.EndSessionEndpoint, notification.LogoutEndpoint);
            }

            if (!string.IsNullOrEmpty(notification.RevocationEndpoint)) {
                response.Add(OpenIdConnectConstants.Metadata.RevocationEndpoint, notification.RevocationEndpoint);
            }

            if (!string.IsNullOrEmpty(notification.TokenEndpoint)) {
                response.Add(OpenIdConnectConstants.Metadata.TokenEndpoint, notification.TokenEndpoint);
            }

            if (!string.IsNullOrEmpty(notification.UserinfoEndpoint)) {
                response.Add(OpenIdConnectConstants.Metadata.UserinfoEndpoint, notification.UserinfoEndpoint);
            }

            response.Add(OpenIdConnectConstants.Metadata.GrantTypesSupported,
                JArray.FromObject(notification.GrantTypes.Distinct()));

            response.Add(OpenIdConnectConstants.Metadata.ResponseModesSupported,
                JArray.FromObject(notification.ResponseModes.Distinct()));

            response.Add(OpenIdConnectConstants.Metadata.ResponseTypesSupported,
                JArray.FromObject(notification.ResponseTypes.Distinct()));

            response.Add(OpenIdConnectConstants.Metadata.SubjectTypesSupported,
                JArray.FromObject(notification.SubjectTypes.Distinct()));

            response.Add(OpenIdConnectConstants.Metadata.ScopesSupported,
                JArray.FromObject(notification.Scopes.Distinct()));

            response.Add(OpenIdConnectConstants.Metadata.IdTokenSigningAlgValuesSupported,
                JArray.FromObject(notification.SigningAlgorithms.Distinct()));

            return await SendConfigurationResponseAsync(request, response);
        }

        private async Task<bool> InvokeCryptographyEndpointAsync() {
            // Metadata requests must be made via GET.
            // See http://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationRequest
            if (!string.Equals(Request.Method, "GET", StringComparison.OrdinalIgnoreCase)) {
                Logger.LogError("The discovery request was rejected because an invalid " +
                                "HTTP method was used: {Method}.", Request.Method);

                return await SendCryptographyResponseAsync(null, new OpenIdConnectMessage {
                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = "Invalid HTTP method: make sure to use GET."
                });
            }

            var request = new OpenIdConnectMessage(Request.Query.ToDictionary());

            var context = new ValidateCryptographyRequestContext(Context, Options);
            await Options.Provider.ValidateCryptographyRequest(context);

            if (!context.IsValidated) {
                Logger.LogError("The discovery request was rejected with the following error: {Error} ; {Description}",
                                /* Error: */ context.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
                                /* Description: */ context.ErrorDescription);

                return await SendCryptographyResponseAsync(request, new OpenIdConnectMessage {
                    Error = context.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = context.ErrorDescription,
                    ErrorUri = context.ErrorUri
                });
            }

            var notification = new HandleCryptographyRequestContext(Context, Options, request);

            foreach (var credentials in Options.SigningCredentials) {
                // Ignore the key if it's not supported.
                if (!(credentials.Key is AsymmetricSecurityKey) &&
                     !credentials.Key.IsSupportedAlgorithm(SecurityAlgorithms.RsaSha256Signature)) {
                    Logger.LogInformation("An unsupported signing key was ignored and excluded " +
                                          "from the key set: {Type}. Only asymmetric security keys " +
                                          "supporting RS256, RS384 or RS512 can be exposed " +
                                          "via the JWKS endpoint.", credentials.Key.GetType().Name);

                    continue;
                }

                RSA algorithm = null;

                // Note: IdentityModel 5 doesn't expose a method allowing to retrieve the underlying algorithm
                // from a generic asymmetric security key. To work around this limitation, try to cast
                // the security key to the built-in IdentityModel types to extract the required RSA instance.
                // See https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/issues/395
                var x509SecurityKey = credentials.Key as X509SecurityKey;
                if (x509SecurityKey != null) {
                    algorithm = (RSA) x509SecurityKey.PublicKey;
                }

                var rsaSecurityKey = credentials.Key as RsaSecurityKey;
                if (rsaSecurityKey != null) {
                    algorithm = rsaSecurityKey.Rsa;

                    // If no RSA instance can be found, create one using
                    // the RSA parameters attached to the security key.
                    if (algorithm == null) {
                        algorithm = RSA.Create();
                        algorithm.ImportParameters(rsaSecurityKey.Parameters);
                    }
                }

                // Skip the key if a RSA instance cannot be extracted.
                if (algorithm == null) {
                    Logger.LogError("A signing key was ignored because it was unable " +
                                    "to provide the requested RSA instance.");

                    continue;
                }

                // Export the RSA public key to create a new JSON Web Key
                // exposing the exponent and the modulus parameters.
                var parameters = algorithm.ExportParameters(includePrivateParameters: false);
                Debug.Assert(parameters.Exponent != null, "RSA.ExportParameters() shouldn't return a null exponent.");
                Debug.Assert(parameters.Modulus != null, "RSA.ExportParameters() shouldn't return a null modulus.");

                var key = new JsonWebKey {
                    Use = JsonWebKeyUseNames.Sig,
                    Kty = JsonWebAlgorithmsKeyTypes.RSA,

                    // Resolve the JWA identifier from the algorithm specified in the credentials.
                    Alg = OpenIdConnectServerHelpers.GetJwtAlgorithm(credentials.Algorithm),

                    // Use the key identifier specified
                    // in the signing credentials.
                    Kid = credentials.Kid,

                    // Both E and N must be base64url-encoded.
                    // See http://tools.ietf.org/html/draft-ietf-jose-json-web-key-31#appendix-A.1
                    E = Base64UrlEncoder.Encode(parameters.Exponent),
                    N = Base64UrlEncoder.Encode(parameters.Modulus)
                };

                // If the signing key is embedded in a X.509 certificate, set
                // the x5t and x5c parameters using the certificate details.
                var x509Certificate = x509SecurityKey?.Certificate;
                if (x509Certificate != null) {
                    // x5t must be base64url-encoded.
                    // See http://tools.ietf.org/html/draft-ietf-jose-json-web-key-31#section-4.8
                    key.X5t = Base64UrlEncoder.Encode(x509SecurityKey.Certificate.GetCertHash());

                    // Unlike E or N, the certificates contained in x5c
                    // must be base64-encoded and not base64url-encoded.
                    // See http://tools.ietf.org/html/draft-ietf-jose-json-web-key-31#section-4.7
                    key.X5c.Add(Convert.ToBase64String(x509SecurityKey.Certificate.RawData));
                }

                notification.Keys.Add(key);
            }

            await Options.Provider.HandleCryptographyRequest(notification);

            if (notification.HandledResponse) {
                return true;
            }

            else if (notification.Skipped) {
                return false;
            }

            var response = new JObject();
            var keys = new JArray();

            foreach (var key in notification.Keys) {
                var item = new JObject();

                // Ensure a key type has been provided.
                // See http://tools.ietf.org/html/draft-ietf-jose-json-web-key-31#section-4.1
                if (string.IsNullOrEmpty(key.Kty)) {
                    Logger.LogError("A JSON Web Key was excluded from the key set because " +
                                    "it didn't contain the mandatory 'kid' parameter.");

                    continue;
                }

                // Create a dictionary associating the
                // JsonWebKey components with their values.
                var parameters = new Dictionary<string, string> {
                    [JsonWebKeyParameterNames.Kid] = key.Kid,
                    [JsonWebKeyParameterNames.Use] = key.Use,
                    [JsonWebKeyParameterNames.Kty] = key.Kty,
                    [JsonWebKeyParameterNames.Alg] = key.Alg,
                    [JsonWebKeyParameterNames.E] = key.E,
                    [JsonWebKeyParameterNames.N] = key.N,
                    [JsonWebKeyParameterNames.X5t] = key.X5t,
                    [JsonWebKeyParameterNames.X5u] = key.X5u
                };

                foreach (var parameter in parameters) {
                    if (!string.IsNullOrEmpty(parameter.Value)) {
                        item.Add(parameter.Key, parameter.Value);
                    }
                }

                if (key.KeyOps.Count != 0) {
                    item.Add(JsonWebKeyParameterNames.KeyOps, JArray.FromObject(key.KeyOps));
                }

                if (key.X5c.Count != 0) {
                    item.Add(JsonWebKeyParameterNames.X5c, JArray.FromObject(key.X5c));
                }

                keys.Add(item);
            }

            response.Add(JsonWebKeyParameterNames.Keys, keys);

            return await SendCryptographyResponseAsync(request, response);
        }

        private Task<bool> SendConfigurationResponseAsync(OpenIdConnectMessage request, OpenIdConnectMessage response) {
            var payload = new JObject();

            foreach (var parameter in response.Parameters) {
                payload[parameter.Key] = parameter.Value;
            }

            return SendConfigurationResponseAsync(request, payload);
        }

        private async Task<bool> SendConfigurationResponseAsync(OpenIdConnectMessage request, JObject response) {
            if (request == null) {
                request = new OpenIdConnectMessage();
            }

            var notification = new ApplyConfigurationResponseContext(Context, Options, request, response);
            await Options.Provider.ApplyConfigurationResponse(notification);

            if (notification.HandledResponse) {
                return true;
            }

            else if (notification.Skipped) {
                return false;
            }

            return await SendPayloadAsync(response);
        }

        private Task<bool> SendCryptographyResponseAsync(OpenIdConnectMessage request, OpenIdConnectMessage response) {
            var payload = new JObject();

            foreach (var parameter in response.Parameters) {
                payload[parameter.Key] = parameter.Value;
            }

            return SendCryptographyResponseAsync(request, payload);
        }

        private async Task<bool> SendCryptographyResponseAsync(OpenIdConnectMessage request, JObject response) {
            if (request == null) {
                request = new OpenIdConnectMessage();
            }

            var notification = new ApplyCryptographyResponseContext(Context, Options, request, response);
            await Options.Provider.ApplyCryptographyResponse(notification);

            if (notification.HandledResponse) {
                return true;
            }

            else if (notification.Skipped) {
                return false;
            }

            return await SendPayloadAsync(response);
        }
    }
}