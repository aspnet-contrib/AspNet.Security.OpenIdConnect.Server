/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Primitives;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Protocols;
using Microsoft.Owin.Security.Infrastructure;
using Newtonsoft.Json.Linq;

namespace Owin.Security.OpenIdConnect.Server
{
    public partial class OpenIdConnectServerHandler : AuthenticationHandler<OpenIdConnectServerOptions>
    {
        private async Task<bool> InvokeConfigurationEndpointAsync()
        {
            // Metadata requests must be made via GET.
            // See http://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationRequest
            if (!string.Equals(Request.Method, "GET", StringComparison.OrdinalIgnoreCase))
            {
                Logger.LogError("The discovery request was rejected because an invalid " +
                                "HTTP method was specified: {Method}.", Request.Method);

                return await SendConfigurationResponseAsync(new OpenIdConnectResponse
                {
                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = "The specified HTTP method is not valid."
                });
            }

            var request = new OpenIdConnectRequest(Request.Query);

            // Note: set the message type before invoking the ExtractConfigurationRequest event.
            request.SetProperty(OpenIdConnectConstants.Properties.MessageType,
                                OpenIdConnectConstants.MessageTypes.ConfigurationRequest);

            // Store the discovery request in the OWIN context.
            Context.SetOpenIdConnectRequest(request);

            var @event = new ExtractConfigurationRequestContext(Context, Options, request);
            await Options.Provider.ExtractConfigurationRequest(@event);

            if (@event.HandledResponse)
            {
                Logger.LogDebug("The discovery request was handled in user code.");

                return true;
            }

            else if (@event.Skipped)
            {
                Logger.LogDebug("The default discovery request handling was skipped from user code.");

                return false;
            }

            else if (@event.IsRejected)
            {
                Logger.LogError("The discovery request was rejected with the following error: {Error} ; {Description}",
                                /* Error: */ @event.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
                                /* Description: */ @event.ErrorDescription);

                return await SendConfigurationResponseAsync(new OpenIdConnectResponse
                {
                    Error = @event.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = @event.ErrorDescription,
                    ErrorUri = @event.ErrorUri
                });
            }

            Logger.LogInformation("The discovery request was successfully extracted " +
                                  "from the HTTP request: {Request}.", request);

            var context = new ValidateConfigurationRequestContext(Context, Options, request);
            await Options.Provider.ValidateConfigurationRequest(context);

            if (context.HandledResponse)
            {
                Logger.LogDebug("The discovery request was handled in user code.");

                return true;
            }

            else if (context.Skipped)
            {
                Logger.LogDebug("The default discovery request handling was skipped from user code.");

                return false;
            }

            else if (context.IsRejected)
            {
                Logger.LogError("The discovery request was rejected with the following error: {Error} ; {Description}",
                                /* Error: */ context.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
                                /* Description: */ context.ErrorDescription);

                return await SendConfigurationResponseAsync(new OpenIdConnectResponse
                {
                    Error = context.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = context.ErrorDescription,
                    ErrorUri = context.ErrorUri
                });
            }

            Logger.LogInformation("The discovery request was successfully validated.");

            var notification = new HandleConfigurationRequestContext(Context, Options, request)
            {
                Issuer = Context.GetIssuer(Options)
            };

            if (Options.AuthorizationEndpointPath.HasValue)
            {
                notification.AuthorizationEndpoint = notification.Issuer.AddPath(Options.AuthorizationEndpointPath);
            }

            if (Options.CryptographyEndpointPath.HasValue)
            {
                notification.CryptographyEndpoint = notification.Issuer.AddPath(Options.CryptographyEndpointPath);
            }

            if (Options.IntrospectionEndpointPath.HasValue)
            {
                notification.IntrospectionEndpoint = notification.Issuer.AddPath(Options.IntrospectionEndpointPath);

                notification.IntrospectionEndpointAuthenticationMethods.Add(
                    OpenIdConnectConstants.ClientAuthenticationMethods.ClientSecretBasic);
                notification.IntrospectionEndpointAuthenticationMethods.Add(
                    OpenIdConnectConstants.ClientAuthenticationMethods.ClientSecretPost);
            }

            if (Options.LogoutEndpointPath.HasValue)
            {
                notification.LogoutEndpoint = notification.Issuer.AddPath(Options.LogoutEndpointPath);
            }

            if (Options.RevocationEndpointPath.HasValue)
            {
                notification.RevocationEndpoint = notification.Issuer.AddPath(Options.RevocationEndpointPath);

                notification.RevocationEndpointAuthenticationMethods.Add(
                    OpenIdConnectConstants.ClientAuthenticationMethods.ClientSecretBasic);
                notification.RevocationEndpointAuthenticationMethods.Add(
                    OpenIdConnectConstants.ClientAuthenticationMethods.ClientSecretPost);
            }

            if (Options.TokenEndpointPath.HasValue)
            {
                notification.TokenEndpoint = notification.Issuer.AddPath(Options.TokenEndpointPath);

                notification.TokenEndpointAuthenticationMethods.Add(
                    OpenIdConnectConstants.ClientAuthenticationMethods.ClientSecretBasic);
                notification.TokenEndpointAuthenticationMethods.Add(
                    OpenIdConnectConstants.ClientAuthenticationMethods.ClientSecretPost);
            }

            if (Options.UserinfoEndpointPath.HasValue)
            {
                notification.UserinfoEndpoint = notification.Issuer.AddPath(Options.UserinfoEndpointPath);
            }

            if (Options.AuthorizationEndpointPath.HasValue)
            {
                notification.GrantTypes.Add(OpenIdConnectConstants.GrantTypes.Implicit);

                if (Options.TokenEndpointPath.HasValue)
                {
                    // Only expose the code grant type and the code challenge methods
                    // if both the authorization and the token endpoints are enabled.
                    notification.GrantTypes.Add(OpenIdConnectConstants.GrantTypes.AuthorizationCode);

                    // Note: supporting S256 is mandatory for authorization servers that implement PKCE.
                    // See https://tools.ietf.org/html/rfc7636#section-4.2 for more information.
                    notification.CodeChallengeMethods.Add(OpenIdConnectConstants.CodeChallengeMethods.Plain);
                    notification.CodeChallengeMethods.Add(OpenIdConnectConstants.CodeChallengeMethods.Sha256);
                }
            }

            if (Options.TokenEndpointPath.HasValue)
            {
                notification.GrantTypes.Add(OpenIdConnectConstants.GrantTypes.RefreshToken);
                notification.GrantTypes.Add(OpenIdConnectConstants.GrantTypes.ClientCredentials);
                notification.GrantTypes.Add(OpenIdConnectConstants.GrantTypes.Password);
            }

            // Only populate response_modes_supported and response_types_supported
            // if the authorization endpoint is available.
            if (Options.AuthorizationEndpointPath.HasValue)
            {
                notification.ResponseModes.Add(OpenIdConnectConstants.ResponseModes.FormPost);
                notification.ResponseModes.Add(OpenIdConnectConstants.ResponseModes.Fragment);
                notification.ResponseModes.Add(OpenIdConnectConstants.ResponseModes.Query);

                notification.ResponseTypes.Add(OpenIdConnectConstants.ResponseTypes.Token);

                // Only expose response types containing code when
                // the token endpoint has not been explicitly disabled.
                if (Options.TokenEndpointPath.HasValue)
                {
                    notification.ResponseTypes.Add(OpenIdConnectConstants.ResponseTypes.Code);

                    notification.ResponseTypes.Add(
                        OpenIdConnectConstants.ResponseTypes.Code + ' ' +
                        OpenIdConnectConstants.ResponseTypes.Token);
                }

                // Only expose the response types containing id_token if an asymmetric signing key is available.
                if (Options.SigningCredentials.Any(credentials => credentials.SigningKey is AsymmetricSecurityKey))
                {
                    notification.ResponseTypes.Add(OpenIdConnectConstants.ResponseTypes.IdToken);

                    notification.ResponseTypes.Add(
                        OpenIdConnectConstants.ResponseTypes.IdToken + ' ' +
                        OpenIdConnectConstants.ResponseTypes.Token);

                    // Only expose response types containing code when
                    // the token endpoint has not been explicitly disabled.
                    if (Options.TokenEndpointPath.HasValue)
                    {
                        notification.ResponseTypes.Add(
                            OpenIdConnectConstants.ResponseTypes.Code + ' ' +
                            OpenIdConnectConstants.ResponseTypes.IdToken);

                        notification.ResponseTypes.Add(
                            OpenIdConnectConstants.ResponseTypes.Code + ' ' +
                            OpenIdConnectConstants.ResponseTypes.IdToken + ' ' +
                            OpenIdConnectConstants.ResponseTypes.Token);
                    }
                }
            }

            notification.Scopes.Add(OpenIdConnectConstants.Scopes.OpenId);

            notification.SubjectTypes.Add(OpenIdConnectConstants.SubjectTypes.Public);

            foreach (var credentials in Options.SigningCredentials)
            {
                // If the signing key is not an asymmetric key, ignore it.
                if (!(credentials.SigningKey is AsymmetricSecurityKey))
                {
                    continue;
                }

                // Try to resolve the JWA algorithm short name. If a null value is returned, ignore it.
                var algorithm = OpenIdConnectServerHelpers.GetJwtAlgorithm(credentials.SignatureAlgorithm);
                if (string.IsNullOrEmpty(algorithm))
                {
                    continue;
                }

                notification.IdTokenSigningAlgorithms.Add(algorithm);
            }

            await Options.Provider.HandleConfigurationRequest(notification);

            if (notification.HandledResponse)
            {
                Logger.LogDebug("The discovery request was handled in user code.");

                return true;
            }

            else if (notification.Skipped)
            {
                Logger.LogDebug("The default discovery request handling was skipped from user code.");

                return false;
            }

            else if (notification.IsRejected)
            {
                Logger.LogError("The discovery request was rejected with the following error: {Error} ; {Description}",
                                /* Error: */ notification.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
                                /* Description: */ notification.ErrorDescription);

                return await SendConfigurationResponseAsync(new OpenIdConnectResponse
                {
                    Error = notification.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = notification.ErrorDescription,
                    ErrorUri = notification.ErrorUri
                });
            }

            var response = new OpenIdConnectResponse
            {
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
                [OpenIdConnectConstants.Metadata.IdTokenSigningAlgValuesSupported] = new JArray(notification.IdTokenSigningAlgorithms),
                [OpenIdConnectConstants.Metadata.CodeChallengeMethodsSupported] = new JArray(notification.CodeChallengeMethods),
                [OpenIdConnectConstants.Metadata.SubjectTypesSupported] = new JArray(notification.SubjectTypes),
                [OpenIdConnectConstants.Metadata.TokenEndpointAuthMethodsSupported] = new JArray(notification.TokenEndpointAuthenticationMethods),
                [OpenIdConnectConstants.Metadata.IntrospectionEndpointAuthMethodsSupported] = new JArray(notification.IntrospectionEndpointAuthenticationMethods),
                [OpenIdConnectConstants.Metadata.RevocationEndpointAuthMethodsSupported] = new JArray(notification.RevocationEndpointAuthenticationMethods)
            };

            foreach (var metadata in notification.Metadata)
            {
                response.SetParameter(metadata.Key, metadata.Value);
            }

            return await SendConfigurationResponseAsync(response);
        }

        private async Task<bool> InvokeCryptographyEndpointAsync()
        {
            // Metadata requests must be made via GET.
            // See http://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationRequest
            if (!string.Equals(Request.Method, "GET", StringComparison.OrdinalIgnoreCase))
            {
                Logger.LogError("The discovery request was rejected because an invalid " +
                                "HTTP method was specified: {Method}.", Request.Method);

                return await SendCryptographyResponseAsync(new OpenIdConnectResponse
                {
                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = "The specified HTTP method is not valid."
                });
            }

            var request = new OpenIdConnectRequest(Request.Query);

            // Note: set the message type before invoking the ExtractCryptographyRequest event.
            request.SetProperty(OpenIdConnectConstants.Properties.MessageType,
                                OpenIdConnectConstants.MessageTypes.CryptographyRequest);

            // Store the discovery request in the OWIN context.
            Context.SetOpenIdConnectRequest(request);

            var @event = new ExtractCryptographyRequestContext(Context, Options, request);
            await Options.Provider.ExtractCryptographyRequest(@event);

            if (@event.HandledResponse)
            {
                Logger.LogDebug("The discovery request was handled in user code.");

                return true;
            }

            else if (@event.Skipped)
            {
                Logger.LogDebug("The default discovery request handling was skipped from user code.");

                return false;
            }

            else if (@event.IsRejected)
            {
                Logger.LogError("The discovery request was rejected with the following error: {Error} ; {Description}",
                                /* Error: */ @event.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
                                /* Description: */ @event.ErrorDescription);

                return await SendCryptographyResponseAsync(new OpenIdConnectResponse
                {
                    Error = @event.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = @event.ErrorDescription,
                    ErrorUri = @event.ErrorUri
                });
            }

            Logger.LogInformation("The discovery request was successfully extracted " +
                                  "from the HTTP request: {Request}.", request);

            var context = new ValidateCryptographyRequestContext(Context, Options, request);
            await Options.Provider.ValidateCryptographyRequest(context);

            if (context.HandledResponse)
            {
                Logger.LogDebug("The discovery request was handled in user code.");

                return true;
            }

            else if (context.Skipped)
            {
                Logger.LogDebug("The default discovery request handling was skipped from user code.");

                return false;
            }

            else if (context.IsRejected)
            {
                Logger.LogError("The discovery request was rejected with the following error: {Error} ; {Description}",
                                /* Error: */ context.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
                                /* Description: */ context.ErrorDescription);

                return await SendCryptographyResponseAsync(new OpenIdConnectResponse
                {
                    Error = context.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = context.ErrorDescription,
                    ErrorUri = context.ErrorUri
                });
            }

            var notification = new HandleCryptographyRequestContext(Context, Options, request);

            foreach (var credentials in Options.SigningCredentials)
            {
                // If the signing key is not an asymmetric key, ignore it.
                if (!(credentials.SigningKey is AsymmetricSecurityKey))
                {
                    continue;
                }

                if (!credentials.SigningKey.IsSupportedAlgorithm(SecurityAlgorithms.RsaSha256Signature))
                {
                    Logger.LogInformation("An unsupported signing key was ignored and excluded from the " +
                                          "key set: {Type}. Only RSA asymmetric security keys can be exposed " +
                                          "via the JWKS endpoint.", credentials.SigningKey.GetType().Name);

                    continue;
                }

                // Try to extract a key identifier from the credentials.
                LocalIdKeyIdentifierClause identifier = null;
                credentials.SigningKeyIdentifier?.TryFind(out identifier);

                // Resolve the underlying algorithm from the security key.
                var algorithm = ((AsymmetricSecurityKey) credentials.SigningKey)
                    .GetAsymmetricAlgorithm(
                        algorithm: SecurityAlgorithms.RsaSha256Signature,
                        privateKey: false) as RSA;

                // Skip the key if an algorithm instance cannot be extracted.
                if (algorithm == null)
                {
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

                var key = new JsonWebKey
                {
                    Use = JsonWebKeyUseNames.Sig,
                    Kty = JsonWebAlgorithmsKeyTypes.RSA,

                    // Resolve the JWA identifier from the algorithm specified in the credentials.
                    Alg = OpenIdConnectServerHelpers.GetJwtAlgorithm(credentials.SignatureAlgorithm),

                    // Use the key identifier specified
                    // in the signing credentials.
                    Kid = identifier?.LocalId,

                    // Note: both E and N must be base64url-encoded.
                    // See https://tools.ietf.org/html/rfc7518#section-6.2.1.2
                    E = Base64UrlEncoder.Encode(parameters.Exponent),
                    N = Base64UrlEncoder.Encode(parameters.Modulus)
                };

                X509Certificate2 certificate = null;

                // Determine whether the signing credentials are directly based on a X.509 certificate.
                if (credentials is X509SigningCredentials x509SigningCredentials)
                {
                    certificate = x509SigningCredentials.Certificate;
                }

                // Determine whether the security key is an asymmetric key embedded in a X.509 certificate.
                else if (credentials.SigningKey is X509SecurityKey x509SecurityKey)
                {
                    certificate = x509SecurityKey.Certificate;
                }

                // Determine whether the security key is an asymmetric key embedded in a X.509 certificate.
                else if (credentials.SigningKey is X509AsymmetricSecurityKey x509AsymmetricSecurityKey)
                {
                    // The X.509 certificate is not directly accessible when using X509AsymmetricSecurityKey.
                    // Reflection is the only way to get the certificate used to create the security key.
                    var field = typeof(X509AsymmetricSecurityKey).GetField(
                        name: "certificate",
                        bindingAttr: BindingFlags.Instance | BindingFlags.NonPublic);
                    Debug.Assert(field != null);

                    certificate = (X509Certificate2) field.GetValue(x509AsymmetricSecurityKey);
                }

                // If the signing key is embedded in a X.509 certificate, set
                // the x5t and x5c parameters using the certificate details.
                if (certificate != null)
                {
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

            if (notification.HandledResponse)
            {
                Logger.LogDebug("The discovery request was handled in user code.");

                return true;
            }

            else if (notification.Skipped)
            {
                Logger.LogDebug("The default discovery request handling was skipped from user code.");

                return false;
            }

            else if (notification.IsRejected)
            {
                Logger.LogError("The discovery request was rejected with the following error: {Error} ; {Description}",
                                /* Error: */ notification.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
                                /* Description: */ notification.ErrorDescription);

                return await SendCryptographyResponseAsync(new OpenIdConnectResponse
                {
                    Error = notification.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = notification.ErrorDescription,
                    ErrorUri = notification.ErrorUri
                });
            }

            var keys = new JArray();

            foreach (var key in notification.Keys)
            {
                var item = new JObject();

                // Ensure a key type has been provided.
                // See https://tools.ietf.org/html/rfc7517#section-4.1
                if (string.IsNullOrEmpty(key.Kty))
                {
                    Logger.LogError("A JSON Web Key was excluded from the key set because " +
                                    "it didn't contain the mandatory 'kid' parameter.");

                    continue;
                }

                // Create a dictionary associating the
                // JsonWebKey components with their values.
                var parameters = new Dictionary<string, string>
                {
                    [JsonWebKeyParameterNames.Kid] = key.Kid,
                    [JsonWebKeyParameterNames.Use] = key.Use,
                    [JsonWebKeyParameterNames.Kty] = key.Kty,
                    [JsonWebKeyParameterNames.KeyOps] = key.KeyOps,
                    [JsonWebKeyParameterNames.Alg] = key.Alg,
                    [JsonWebKeyParameterNames.E] = key.E,
                    [JsonWebKeyParameterNames.N] = key.N,
                    [JsonWebKeyParameterNames.X5t] = key.X5t,
                    [JsonWebKeyParameterNames.X5u] = key.X5u
                };

                foreach (var parameter in parameters)
                {
                    if (!string.IsNullOrEmpty(parameter.Value))
                    {
                        item.Add(parameter.Key, parameter.Value);
                    }
                }

                if (key.X5c.Count != 0)
                {
                    item.Add(JsonWebKeyParameterNames.X5c, new JArray(key.X5c));
                }

                keys.Add(item);
            }

            // Note: AddParameter() is used here to ensure the mandatory "keys" node
            // is returned to the caller, even if the key set doesn't expose any key.
            // See https://tools.ietf.org/html/rfc7517#section-5 for more information.
            var response = new OpenIdConnectResponse();
            response.AddParameter(OpenIdConnectConstants.Parameters.Keys, keys);

            return await SendCryptographyResponseAsync(response);
        }

        private async Task<bool> SendConfigurationResponseAsync(OpenIdConnectResponse response)
        {
            var request = Context.GetOpenIdConnectRequest();
            Context.SetOpenIdConnectResponse(response);

            response.SetProperty(OpenIdConnectConstants.Properties.MessageType,
                                 OpenIdConnectConstants.MessageTypes.ConfigurationResponse);

            var notification = new ApplyConfigurationResponseContext(Context, Options, request, response);
            await Options.Provider.ApplyConfigurationResponse(notification);

            if (notification.HandledResponse)
            {
                Logger.LogDebug("The discovery request was handled in user code.");

                return true;
            }

            else if (notification.Skipped)
            {
                Logger.LogDebug("The default discovery request handling was skipped from user code.");

                return false;
            }

            Logger.LogInformation("The discovery response was successfully returned: {Response}.", response);

            return await SendPayloadAsync(response);
        }

        private async Task<bool> SendCryptographyResponseAsync(OpenIdConnectResponse response)
        {
            var request = Context.GetOpenIdConnectRequest();
            Context.SetOpenIdConnectResponse(response);

            response.SetProperty(OpenIdConnectConstants.Properties.MessageType,
                                 OpenIdConnectConstants.MessageTypes.CryptographyResponse);

            var notification = new ApplyCryptographyResponseContext(Context, Options, request, response);
            await Options.Provider.ApplyCryptographyResponse(notification);

            if (notification.HandledResponse)
            {
                Logger.LogDebug("The discovery request was handled in user code.");

                return true;
            }

            else if (notification.Skipped)
            {
                Logger.LogDebug("The default discovery request handling was skipped from user code.");

                return false;
            }

            Logger.LogInformation("The discovery response was successfully returned: {Response}.", response);

            return await SendPayloadAsync(response);
        }
    }
}
