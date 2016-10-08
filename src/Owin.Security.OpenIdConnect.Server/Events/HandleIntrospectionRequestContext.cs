/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.IdentityModel.Tokens;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Newtonsoft.Json.Linq;
using Owin.Security.OpenIdConnect.Extensions;

namespace Owin.Security.OpenIdConnect.Server {
    /// <summary>
    /// An event raised before the authorization server handles
    /// the request made to the token introspection endpoint.
    /// </summary>
    public class HandleIntrospectionRequestContext : BaseValidatingContext {
        /// <summary>
        /// Creates an instance of this context.
        /// </summary>
        public HandleIntrospectionRequestContext(
            IOwinContext context,
            OpenIdConnectServerOptions options,
            OpenIdConnectRequest request,
            AuthenticationTicket ticket)
            : base(context, options, request) {
            Ticket = ticket;
            Validate();
        }

        /// <summary>
        /// Gets or sets the authentication ticket.
        /// </summary>
        public AuthenticationTicket Ticket { get; set; }

        /// <summary>
        /// Gets the list of claims returned to the caller.
        /// </summary>
        public JObject Claims { get; } = new JObject();

        /// <summary>
        /// Gets or sets the flag indicating
        /// whether the token is active or not.
        /// </summary>
        public bool? Active {
            get { return (bool?) Claims[OpenIdConnectConstants.Claims.Active]; }
            set {
                if (value == null) {
                    Claims.Remove(OpenIdConnectConstants.Claims.Active);

                    return;
                }

                Claims[OpenIdConnectConstants.Claims.Active] = value;
            }
        }

        /// <summary>
        /// Gets the list of audiences returned to the caller
        /// as part of the "aud" claim, if applicable.
        /// </summary>
        public JArray Audiences {
            get {
                var value = (JArray) Claims[OpenIdConnectConstants.Claims.Audience];
                if (value == null) {
                    value = new JArray();

                    Claims[OpenIdConnectConstants.Claims.Audience] = value;
                }

                return value;
            }
        }

        /// <summary>
        /// Gets or sets the "exp" claim
        /// returned to the caller, if applicable.
        /// </summary>
        public DateTimeOffset? ExpiresAt {
            get {
                var value = (long?) Claims[OpenIdConnectConstants.Claims.ExpiresAt];
                if (value == null) {
                    return null;
                }

                return EpochTime.DateTime(value.Value);
            }

            set {
                if (value == null) {
                    Claims.Remove(OpenIdConnectConstants.Claims.ExpiresAt);

                    return;
                }

                Claims[OpenIdConnectConstants.Claims.ExpiresAt] = EpochTime.GetIntDate(value.Value.UtcDateTime);
            }
        }

        /// <summary>
        /// Gets or sets the "iat" claim
        /// returned to the caller, if applicable.
        /// </summary>
        public DateTimeOffset? IssuedAt {
            get {
                var value = (long?) Claims[OpenIdConnectConstants.Claims.IssuedAt];
                if (value == null) {
                    return null;
                }

                return EpochTime.DateTime(value.Value);
            }

            set {
                if (value == null) {
                    Claims.Remove(OpenIdConnectConstants.Claims.IssuedAt);

                    return;
                }

                Claims[OpenIdConnectConstants.Claims.IssuedAt] = EpochTime.GetIntDate(value.Value.UtcDateTime);
            }
        }

        /// <summary>
        /// Gets or sets the "iss" claim
        /// returned to the caller, if applicable.
        /// </summary>
        public string Issuer {
            get { return (string) Claims[OpenIdConnectConstants.Claims.Issuer]; }
            set {
                if (value == null) {
                    Claims.Remove(OpenIdConnectConstants.Claims.Issuer);

                    return;
                }

                Claims[OpenIdConnectConstants.Claims.Issuer] = value;
            }
        }

        /// <summary>
        /// Gets or sets the "nbf" claim
        /// returned to the caller, if applicable.
        /// </summary>
        public DateTimeOffset? NotBefore {
            get {
                var value = (long?) Claims[OpenIdConnectConstants.Claims.NotBefore];
                if (value == null) {
                    return null;
                }

                return EpochTime.DateTime(value.Value);
            }

            set {
                if (value == null) {
                    Claims.Remove(OpenIdConnectConstants.Claims.NotBefore);

                    return;
                }

                Claims[OpenIdConnectConstants.Claims.NotBefore] = EpochTime.GetIntDate(value.Value.UtcDateTime);
            }
        }

        /// <summary>
        /// Gets or sets the "scope" claim
        /// returned to the caller, if applicable.
        /// </summary>
        public string Scope {
            get { return (string) Claims[OpenIdConnectConstants.Claims.Scope]; }
            set {
                if (value == null) {
                    Claims.Remove(OpenIdConnectConstants.Claims.Scope);

                    return;
                }

                Claims[OpenIdConnectConstants.Claims.Scope] = value;
            }
        }

        /// <summary>
        /// Gets or sets the "sub" claim
        /// returned to the caller, if applicable.
        /// </summary>
        public string Subject {
            get { return (string) Claims[OpenIdConnectConstants.Claims.Subject]; }
            set {
                if (value == null) {
                    Claims.Remove(OpenIdConnectConstants.Claims.Subject);

                    return;
                }

                Claims[OpenIdConnectConstants.Claims.Subject] = value;
            }
        }

        /// <summary>
        /// Gets or sets the "jti" claim
        /// returned to the caller, if applicable.
        /// </summary>
        public string TokenId {
            get { return (string) Claims[OpenIdConnectConstants.Claims.JwtId]; }
            set {
                if (value == null) {
                    Claims.Remove(OpenIdConnectConstants.Claims.JwtId);

                    return;
                }

                Claims[OpenIdConnectConstants.Claims.JwtId] = value;
            }
        }

        /// <summary>
        /// Gets or sets the "token_type" claim
        /// returned to the caller, if applicable.
        /// </summary>
        public string TokenType {
            get { return (string) Claims[OpenIdConnectConstants.Claims.TokenType]; }
            set {
                if (value == null) {
                    Claims.Remove(OpenIdConnectConstants.Claims.TokenType);

                    return;
                }

                Claims[OpenIdConnectConstants.Claims.TokenType] = value;
            }
        }

        /// <summary>
        /// Gets or sets the "username" claim
        /// returned to the caller, if applicable.
        /// </summary>
        public string Username {
            get { return (string) Claims[OpenIdConnectConstants.Claims.Username]; }
            set {
                if (value == null) {
                    Claims.Remove(OpenIdConnectConstants.Claims.Username);

                    return;
                }

                Claims[OpenIdConnectConstants.Claims.Username] = value;
            }
        }
    }
}
