/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Primitives;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Logging;
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

                return await SendConfigurationResponseAsync(new OpenIdConnectResponse {
                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = "Invalid HTTP method: make sure to use GET."
                });
            }

            var request = new OpenIdConnectRequest(Request.Query);

            // Note: set the message type before invoking the ExtractConfigurationRequest event.
            request.SetProperty(OpenIdConnectConstants.Properties.MessageType,
                                OpenIdConnectConstants.MessageTypes.Configuration);

            // Store the discovery request in the ASP.NET context.
            Context.SetOpenIdConnectRequest(request);

            var @event = new ExtractConfigurationRequestContext(Context, Options, request);
            await Options.Provider.ExtractConfigurationRequest(@event);

            if (@event.HandledResponse) {
                return true;
            }

            else if (@event.Skipped) {
                return false;
            }

            else if (@event.IsRejected) {
                Logger.LogError("The discovery request was rejected with the following error: {Error} ; {Description}",
                                /* Error: */ @event.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
                                /* Description: */ @event.ErrorDescription);

                return await SendConfigurationResponseAsync(new OpenIdConnectResponse {
                    Error = @event.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = @event.ErrorDescription,
                    ErrorUri = @event.ErrorUri
                });
            }

            var context = new ValidateConfigurationRequestContext(Context, Options, request);
            await Options.Provider.ValidateConfigurationRequest(context);

            if (context.HandledResponse) {
                return true;
            }

            else if (context.Skipped) {
                return false;
            }

            else if (!context.IsValidated) {
                Logger.LogError("The discovery request was rejected with the following error: {Error} ; {Description}",
                                /* Error: */ context.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
                                /* Description: */ context.ErrorDescription);

                return await SendConfigurationResponseAsync(new OpenIdConnectResponse {
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
                notification.GrantTypes.Add(OpenIdConnectConstants.GrantTypes.ClientCredentials);
                notification.GrantTypes.Add(OpenIdConnectConstants.GrantTypes.Password);
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

            // Note: supporting S256 is mandatory for authorization servers that implement PKCE.
            // See https://tools.ietf.org/html/rfc7636#section-4.2 for more information.
            notification.CodeChallengeMethods.Add(OpenIdConnectConstants.CodeChallengeMethods.Plain);
            notification.CodeChallengeMethods.Add(OpenIdConnectConstants.CodeChallengeMethods.Sha256);

            foreach (var credentials in Options.SigningCredentials) {
                // Try to resolve the JWA algorithm short name. If a null value is returned, ignore it.
                var algorithm = OpenIdConnectServerHelpers.GetJwtAlgorithm(credentials.Algorithm);
                if (string.IsNullOrEmpty(algorithm)) {
                    continue;
                }

                notification.SigningAlgorithms.Add(algorithm);
            }

            await Options.Provider.HandleConfigurationRequest(notification);

            if (notification.HandledResponse) {
                return true;
            }

            else if (notification.Skipped) {
                return false;
            }

            else if (notification.IsRejected) {
                Logger.LogError("The discovery request was rejected with the following error: {Error} ; {Description}",
                                /* Error: */ notification.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
                                /* Description: */ notification.ErrorDescription);

                return await SendConfigurationResponseAsync(new OpenIdConnectResponse {
                    Error = notification.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = notification.ErrorDescription,
                    ErrorUri = notification.ErrorUri
                });
            }

            var response = new OpenIdConnectResponse {
                [OpenIdConnectConstants.Metadata.Issuer] = notification.Issuer,
                [OpenIdConnectConstants.Metadata.AuthorizationEndpoint] = notification.AuthorizationEndpoint,
                [OpenIdConnectConstants.Metadata.TokenEndpoint] = notification.TokenEndpoint,
                [OpenIdConnectConstants.Metadata.IntrospectionEndpoint] = notification.IntrospectionEndpoint,
                [OpenIdConnectConstants.Metadata.EndSessionEndpoint] = notification.LogoutEndpoint,
                [OpenIdConnectConstants.Metadata.RevocationEndpoint] = notification.RevocationEndpoint,
                [OpenIdConnectConstants.Metadata.UserinfoEndpoint] = notification.UserinfoEndpoint,
                [OpenIdConnectConstants.Metadata.JwksUri] = notification.CryptographyEndpoint,
                [OpenIdConnectConstants.Metadata.GrantTypesSupported] = new JArray(notification.GrantTypes),
                [OpenIdConnectConstants.Metadata.ResponseTypesSupported] = new JArray(notification.ResponseTypes),
                [OpenIdConnectConstants.Metadata.ResponseModesSupported] = new JArray(notification.ResponseModes),
                [OpenIdConnectConstants.Metadata.ScopesSupported] = new JArray(notification.Scopes),
                [OpenIdConnectConstants.Metadata.IdTokenSigningAlgValuesSupported] = new JArray(notification.SigningAlgorithms),
                [OpenIdConnectConstants.Metadata.CodeChallengeMethodsSupported] = new JArray(notification.CodeChallengeMethods),
                [OpenIdConnectConstants.Metadata.SubjectTypesSupported] = new JArray(notification.SubjectTypes)
            };

            foreach (var metadata in notification.Metadata) {
                response.AddParameter(metadata.Key, metadata.Value);
            }

            return await SendConfigurationResponseAsync(response);
        }

        private async Task<bool> InvokeCryptographyEndpointAsync() {
            // Metadata requests must be made via GET.
            // See http://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationRequest
            if (!string.Equals(Request.Method, "GET", StringComparison.OrdinalIgnoreCase)) {
                Logger.LogError("The discovery request was rejected because an invalid " +
                                "HTTP method was used: {Method}.", Request.Method);

                return await SendCryptographyResponseAsync(new OpenIdConnectResponse {
                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = "Invalid HTTP method: make sure to use GET."
                });
            }

            var request = new OpenIdConnectRequest(Request.Query);

            // Note: set the message type before invoking the ExtractCryptographyRequest event.
            request.SetProperty(OpenIdConnectConstants.Properties.MessageType,
                                OpenIdConnectConstants.MessageTypes.Cryptography);

            // Store the discovery request in the ASP.NET context.
            Context.SetOpenIdConnectRequest(request);

            var @event = new ExtractCryptographyRequestContext(Context, Options, request);
            await Options.Provider.ExtractCryptographyRequest(@event);

            if (@event.HandledResponse) {
                return true;
            }

            else if (@event.Skipped) {
                return false;
            }

            else if (@event.IsRejected) {
                Logger.LogError("The discovery request was rejected with the following error: {Error} ; {Description}",
                                /* Error: */ @event.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
                                /* Description: */ @event.ErrorDescription);

                return await SendCryptographyResponseAsync(new OpenIdConnectResponse {
                    Error = @event.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = @event.ErrorDescription,
                    ErrorUri = @event.ErrorUri
                });
            }

            var context = new ValidateCryptographyRequestContext(Context, Options, request);
            await Options.Provider.ValidateCryptographyRequest(context);

            if (context.HandledResponse) {
                return true;
            }

            else if (context.Skipped) {
                return false;
            }

            else if (!context.IsValidated) {
                Logger.LogError("The discovery request was rejected with the following error: {Error} ; {Description}",
                                /* Error: */ context.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
                                /* Description: */ context.ErrorDescription);

                return await SendCryptographyResponseAsync(new OpenIdConnectResponse {
                    Error = context.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = context.ErrorDescription,
                    ErrorUri = context.ErrorUri
                });
            }

            var notification = new HandleCryptographyRequestContext(Context, Options, request);

            foreach (var credentials in Options.SigningCredentials) {
                // Ignore the key if it's not supported.
#if SUPPORTS_ECDSA
                if (!credentials.Key.IsSupportedAlgorithm(SecurityAlgorithms.RsaSha256Signature) &&
                    !credentials.Key.IsSupportedAlgorithm(SecurityAlgorithms.EcdsaSha256Signature) &&
                    !credentials.Key.IsSupportedAlgorithm(SecurityAlgorithms.EcdsaSha384Signature) &&
                    !credentials.Key.IsSupportedAlgorithm(SecurityAlgorithms.EcdsaSha512Signature)) {
                    Logger.LogInformation("An unsupported signing key was ignored and excluded from the " +
                                          "key set: {Type}. Only RSA and ECDSA asymmetric security keys " +
                                          "can be exposed via the JWKS endpoint.", credentials.Key.GetType().Name);

                    continue;
                }
#else
                if (!credentials.Key.IsSupportedAlgorithm(SecurityAlgorithms.RsaSha256Signature)) {
                    Logger.LogInformation("An unsupported signing key was ignored and excluded from the " +
                                          "key set: {Type}. Only RSA asymmetric security keys can be exposed " +
                                          "via the JWKS endpoint.", credentials.Key.GetType().Name);

                    continue;
                }
#endif

                var key = new JsonWebKey {
                    Use = JsonWebKeyUseNames.Sig,

                    // Resolve the JWA identifier from the algorithm specified in the credentials.
                    Alg = OpenIdConnectServerHelpers.GetJwtAlgorithm(credentials.Algorithm),

                    // Use the key identifier specified in the signing credentials.
                    Kid = credentials.Kid,
                };

                if (credentials.Key.IsSupportedAlgorithm(SecurityAlgorithms.RsaSha256Signature)) {
                    RSA algorithm = null;

                    // Note: IdentityModel 5 doesn't expose a method allowing to retrieve the underlying algorithm
                    // from a generic asymmetric security key. To work around this limitation, try to cast
                    // the security key to the built-in IdentityModel types to extract the required RSA instance.
                    // See https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/issues/395
                    var x509SecurityKey = credentials.Key as X509SecurityKey;
                    if (x509SecurityKey != null) {
                        algorithm = x509SecurityKey.PublicKey as RSA;
                    }

                    var rsaSecurityKey = credentials.Key as RsaSecurityKey;
                    if (rsaSecurityKey != null) {
                        algorithm = rsaSecurityKey.Rsa;

                        // If no RSA instance can be found, create one using
                        // the RSA parameters attached to the security key.
                        if (algorithm == null) {
                            var rsa = RSA.Create();
                            rsa.ImportParameters(rsaSecurityKey.Parameters);
                            algorithm = rsa;
                        }
                    }

                    // Skip the key if an algorithm instance cannot be extracted.
                    if (algorithm == null) {
                        Logger.LogWarning("A signing key was ignored because it was unable " +
                                          "to provide the requested algorithm instance.");

                        continue;
                    }

                    // Export the RSA public key to create a new JSON Web Key
                    // exposing the exponent and the modulus parameters.
                    var parameters = algorithm.ExportParameters(includePrivateParameters: false);

                    Debug.Assert(parameters.Exponent != null &&
                                 parameters.Modulus != null,
                        "RSA.ExportParameters() shouldn't return null parameters.");

                    key.Kty = JsonWebAlgorithmsKeyTypes.RSA;

                    // Note: both E and N must be base64url-encoded.
                    // See https://tools.ietf.org/html/rfc7518#section-6.3.1.1
                    key.E = Base64UrlEncoder.Encode(parameters.Exponent);
                    key.N = Base64UrlEncoder.Encode(parameters.Modulus);
                }

#if SUPPORTS_ECDSA
                else if (credentials.Key.IsSupportedAlgorithm(SecurityAlgorithms.EcdsaSha256Signature) ||
                         credentials.Key.IsSupportedAlgorithm(SecurityAlgorithms.EcdsaSha384Signature) ||
                         credentials.Key.IsSupportedAlgorithm(SecurityAlgorithms.EcdsaSha512Signature)) {
                    ECDsa algorithm = null;

                    var x509SecurityKey = credentials.Key as X509SecurityKey;
                    if (x509SecurityKey != null) {
                        algorithm = x509SecurityKey.PublicKey as ECDsa;
                    }

                    var ecdsaSecurityKey = credentials.Key as ECDsaSecurityKey;
                    if (ecdsaSecurityKey != null) {
                        algorithm = ecdsaSecurityKey.ECDsa;
                    }

                    // Skip the key if an algorithm instance cannot be extracted.
                    if (algorithm == null) {
                        Logger.LogWarning("A signing key was ignored because it was unable " +
                                          "to provide the requested algorithm instance.");

                        continue;
                    }

                    // Export the ECDsa public key to create a new JSON Web Key
                    // exposing the coordinates of the point on the curve.
                    var parameters = algorithm.ExportParameters(includePrivateParameters: false);

                    Debug.Assert(parameters.Q.X != null &&
                                 parameters.Q.Y != null,
                        "ECDsa.ExportParameters() shouldn't return null coordinates.");

                    key.Kty = JsonWebAlgorithmsKeyTypes.EllipticCurve;
                    key.Crv = OpenIdConnectServerHelpers.GetJwtAlgorithmCurve(parameters.Curve);

                    // Note: both X and Y must be base64url-encoded.
                    // See https://tools.ietf.org/html/rfc7518#section-6.2.1.2
                    key.X = Base64UrlEncoder.Encode(parameters.Q.X);
                    key.Y = Base64UrlEncoder.Encode(parameters.Q.Y);
                }
#endif

                // If the signing key is embedded in a X.509 certificate, set
                // the x5t and x5c parameters using the certificate details.
                var certificate = (credentials.Key as X509SecurityKey)?.Certificate;
                if (certificate != null) {
                    // x5t must be base64url-encoded.
                    // See https://tools.ietf.org/html/rfc7517#section-4.8
                    key.X5t = Base64UrlEncoder.Encode(certificate.GetCertHash());

                    // Unlike E or N, the certificates contained in x5c
                    // must be base64-encoded and not base64url-encoded.
                    // See https://tools.ietf.org/html/rfc7517#section-4.7
                    key.X5c.Add(Convert.ToBase64String(certificate.RawData));
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

            else if (notification.IsRejected) {
                Logger.LogError("The discovery request was rejected with the following error: {Error} ; {Description}",
                                /* Error: */ notification.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
                                /* Description: */ notification.ErrorDescription);

                return await SendCryptographyResponseAsync(new OpenIdConnectResponse {
                    Error = notification.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = notification.ErrorDescription,
                    ErrorUri = notification.ErrorUri
                });
            }

            var keys = new JArray();

            foreach (var key in notification.Keys) {
                var item = new JObject();

                // Ensure a key type has been provided.
                // See https://tools.ietf.org/html/rfc7517#section-4.1
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
                    [JsonWebKeyParameterNames.Crv] = key.Crv,
                    [JsonWebKeyParameterNames.E] = key.E,
                    [JsonWebKeyParameterNames.N] = key.N,
                    [JsonWebKeyParameterNames.X] = key.X,
                    [JsonWebKeyParameterNames.Y] = key.Y,
                    [JsonWebKeyParameterNames.X5t] = key.X5t,
                    [JsonWebKeyParameterNames.X5u] = key.X5u
                };

                foreach (var parameter in parameters) {
                    if (!string.IsNullOrEmpty(parameter.Value)) {
                        item.Add(parameter.Key, parameter.Value);
                    }
                }

                if (key.KeyOps.Count != 0) {
                    item.Add(JsonWebKeyParameterNames.KeyOps, new JArray(key.KeyOps));
                }

                if (key.X5c.Count != 0) {
                    item.Add(JsonWebKeyParameterNames.X5c, new JArray(key.X5c));
                }

                keys.Add(item);
            }

            return await SendCryptographyResponseAsync(new OpenIdConnectResponse {
                [OpenIdConnectConstants.Parameters.Keys] = keys
            });
        }

        private async Task<bool> SendConfigurationResponseAsync(OpenIdConnectResponse response) {
            var request = Context.GetOpenIdConnectRequest();
            Context.SetOpenIdConnectResponse(response);

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

        private async Task<bool> SendCryptographyResponseAsync(OpenIdConnectResponse response) {
            var request = Context.GetOpenIdConnectRequest();
            Context.SetOpenIdConnectResponse(response);

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
