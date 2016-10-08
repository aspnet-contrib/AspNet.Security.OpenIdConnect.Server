/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using Microsoft.Owin;
using Newtonsoft.Json.Linq;
using Owin.Security.OpenIdConnect.Extensions;

namespace Owin.Security.OpenIdConnect.Server {
    /// <summary>
    /// An event raised before the authorization server handles
    /// the request made to the configuration metadata endpoint.
    /// </summary>
    public class HandleConfigurationRequestContext : BaseValidatingContext {
        /// <summary>
        /// Creates an instance of this context.
        /// </summary>
        public HandleConfigurationRequestContext(
            IOwinContext context,
            OpenIdConnectServerOptions options,
            OpenIdConnectRequest request)
            : base(context, options, request) {
            Validate();
        }

        /// <summary>
        /// Gets the list of properties returned to the client application.
        /// </summary>
        public JObject Metadata { get; } = new JObject();

        /// <summary>
        /// Gets or sets the authorization endpoint address.
        /// </summary>
        public string AuthorizationEndpoint {
            get { return (string) Metadata[OpenIdConnectConstants.Metadata.AuthorizationEndpoint]; }
            set {
                if (value == null) {
                    Metadata.Remove(OpenIdConnectConstants.Metadata.AuthorizationEndpoint);

                    return;
                }

                Metadata[OpenIdConnectConstants.Metadata.AuthorizationEndpoint] = value;
            }
        }

        /// <summary>
        /// Gets or sets the JWKS endpoint address.
        /// </summary>
        public string CryptographyEndpoint {
            get { return (string) Metadata[OpenIdConnectConstants.Metadata.JwksUri]; }
            set {
                if (value == null) {
                    Metadata.Remove(OpenIdConnectConstants.Metadata.JwksUri);

                    return;
                }

                Metadata[OpenIdConnectConstants.Metadata.JwksUri] = value;
            }
        }

        /// <summary>
        /// Gets or sets the introspection endpoint address.
        /// </summary>
        public string IntrospectionEndpoint {
            get { return (string) Metadata[OpenIdConnectConstants.Metadata.IntrospectionEndpoint]; }
            set {
                if (value == null) {
                    Metadata.Remove(OpenIdConnectConstants.Metadata.IntrospectionEndpoint);

                    return;
                }

                Metadata[OpenIdConnectConstants.Metadata.IntrospectionEndpoint] = value;
            }
        }

        /// <summary>
        /// Gets or sets the logout endpoint address.
        /// </summary>
        public string LogoutEndpoint {
            get { return (string) Metadata[OpenIdConnectConstants.Metadata.EndSessionEndpoint]; }
            set {
                if (value == null) {
                    Metadata.Remove(OpenIdConnectConstants.Metadata.EndSessionEndpoint);

                    return;
                }

                Metadata[OpenIdConnectConstants.Metadata.EndSessionEndpoint] = value;
            }
        }

        /// <summary>
        /// Gets or sets the revocation endpoint address.
        /// </summary>
        public string RevocationEndpoint {
            get { return (string) Metadata[OpenIdConnectConstants.Metadata.RevocationEndpoint]; }
            set {
                if (value == null) {
                    Metadata.Remove(OpenIdConnectConstants.Metadata.RevocationEndpoint);

                    return;
                }

                Metadata[OpenIdConnectConstants.Metadata.RevocationEndpoint] = value;
            }
        }

        /// <summary>
        /// Gets or sets the token endpoint address.
        /// </summary>
        public string TokenEndpoint {
            get { return (string) Metadata[OpenIdConnectConstants.Metadata.TokenEndpoint]; }
            set {
                if (value == null) {
                    Metadata.Remove(OpenIdConnectConstants.Metadata.TokenEndpoint);

                    return;
                }

                Metadata[OpenIdConnectConstants.Metadata.TokenEndpoint] = value;
            }
        }

        /// <summary>
        /// Gets or sets the userinfo endpoint address.
        /// </summary>
        public string UserinfoEndpoint {
            get { return (string) Metadata[OpenIdConnectConstants.Metadata.UserinfoEndpoint]; }
            set {
                if (value == null) {
                    Metadata.Remove(OpenIdConnectConstants.Metadata.UserinfoEndpoint);

                    return;
                }

                Metadata[OpenIdConnectConstants.Metadata.UserinfoEndpoint] = value;
            }
        }

        /// <summary>
        /// Gets or sets the issuer address.
        /// </summary>
        public string Issuer {
            get { return (string) Metadata[OpenIdConnectConstants.Metadata.Issuer]; }
            set {
                if (value == null) {
                    Metadata.Remove(OpenIdConnectConstants.Metadata.Issuer);

                    return;
                }

                Metadata[OpenIdConnectConstants.Metadata.Issuer] = value;
            }
        }

        /// <summary>
        /// Gets a list of the code challenge methods
        /// supported by the authorization server.
        /// </summary>
        public JArray CodeChallengeMethods {
            get {
                var value = (JArray) Metadata[OpenIdConnectConstants.Metadata.CodeChallengeMethodsSupported];
                if (value == null) {
                    value = new JArray();

                    Metadata[OpenIdConnectConstants.Metadata.CodeChallengeMethodsSupported] = value;
                }

                return value;
            }
        }

        /// <summary>
        /// Gets a list of the grant types
        /// supported by the authorization server.
        /// </summary>
        public JArray GrantTypes {
            get {
                var value = (JArray) Metadata[OpenIdConnectConstants.Metadata.GrantTypesSupported];
                if (value == null) {
                    value = new JArray();

                    Metadata[OpenIdConnectConstants.Metadata.GrantTypesSupported] = value;
                }

                return value;
            }
        }

        /// <summary>
        /// Gets a list of the response modes
        /// supported by the authorization server.
        /// </summary>
        public JArray ResponseModes {
            get {
                var value = (JArray) Metadata[OpenIdConnectConstants.Metadata.ResponseModesSupported];
                if (value == null) {
                    value = new JArray();

                    Metadata[OpenIdConnectConstants.Metadata.ResponseModesSupported] = value;
                }

                return value;
            }
        }

        /// <summary>
        /// Gets a list of the response types
        /// supported by the authorization server.
        /// </summary>
        public JArray ResponseTypes {
            get {
                var value = (JArray) Metadata[OpenIdConnectConstants.Metadata.ResponseTypesSupported];
                if (value == null) {
                    value = new JArray();

                    Metadata[OpenIdConnectConstants.Metadata.ResponseTypesSupported] = value;
                }

                return value;
            }
        }

        /// <summary>
        /// Gets a list of the scope values
        /// supported by the authorization server.
        /// </summary>
        public JArray Scopes {
            get {
                var value = (JArray) Metadata[OpenIdConnectConstants.Metadata.ScopesSupported];
                if (value == null) {
                    value = new JArray();

                    Metadata[OpenIdConnectConstants.Metadata.ScopesSupported] = value;
                }

                return value;
            }
        }

        /// <summary>
        /// Gets a list of the signing algorithms
        /// supported by the authorization server.
        /// </summary>
        public JArray SigningAlgorithms {
            get {
                var value = (JArray) Metadata[OpenIdConnectConstants.Metadata.IdTokenSigningAlgValuesSupported];
                if (value == null) {
                    value = new JArray();

                    Metadata[OpenIdConnectConstants.Metadata.IdTokenSigningAlgValuesSupported] = value;
                }

                return value;
            }
        }

        /// <summary>
        /// Gets a list of the subject types
        /// supported by the authorization server.
        /// </summary>
        public JArray SubjectTypes {
            get {
                var value = (JArray) Metadata[OpenIdConnectConstants.Metadata.SubjectTypesSupported];
                if (value == null) {
                    value = new JArray();

                    Metadata[OpenIdConnectConstants.Metadata.SubjectTypesSupported] = value;
                }

                return value;
            }
        }
    }
}
