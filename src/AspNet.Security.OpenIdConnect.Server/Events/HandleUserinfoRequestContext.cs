/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using AspNet.Security.OpenIdConnect.Extensions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Newtonsoft.Json.Linq;

namespace AspNet.Security.OpenIdConnect.Server {
    /// <summary>
    /// An event raised after the Authorization Server has processed the request, but before it is passed on to the web application.
    /// Calling RequestCompleted will prevent the request from passing on to the web application.
    /// </summary>
    public class HandleUserinfoRequestContext : BaseValidatingContext {
        /// <summary>
        /// Creates an instance of this context
        /// </summary>
        public HandleUserinfoRequestContext(
            HttpContext context,
            OpenIdConnectServerOptions options,
            OpenIdConnectRequest request,
            AuthenticationTicket ticket)
            : base(context, options, request) {
            Ticket = ticket;
            Validate();
        }

        /// <summary>
        /// Gets the list of claims returned to the client application.
        /// </summary>
        public JObject Claims { get; } = new JObject();

        /// <summary>
        /// Gets or sets the value used for the "address" claim.
        /// Note: this value should only be populated if the "address"
        /// scope was requested and accepted by the user agent.
        /// </summary>
        public JObject Address {
            get { return (JObject) Claims[OpenIdConnectConstants.Claims.Address]; }
            set {
                if (value == null) {
                    Claims.Remove(OpenIdConnectConstants.Claims.Address);

                    return;
                }

                Claims[OpenIdConnectConstants.Claims.Address] = value;
            }
        }

        /// <summary>
        /// Gets the values used for the "aud" claim.
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
        /// Gets or sets the value used for the "birthdate" claim.
        /// Note: this value should only be populated if the "profile"
        /// scope was requested and accepted by the user agent.
        /// </summary>
        public string BirthDate {
            get { return (string) Claims[OpenIdConnectConstants.Claims.Birthdate]; }
            set {
                if (value == null) {
                    Claims.Remove(OpenIdConnectConstants.Claims.Birthdate);

                    return;
                }

                Claims[OpenIdConnectConstants.Claims.Birthdate] = value;
            }
        }

        /// <summary>
        /// Gets or sets the value used for the "email" claim.
        /// Note: this value should only be populated if the "email"
        /// scope was requested and accepted by the user agent.
        /// </summary>
        public string Email {
            get { return (string) Claims[OpenIdConnectConstants.Claims.Email]; }
            set {
                if (value == null) {
                    Claims.Remove(OpenIdConnectConstants.Claims.Email);

                    return;
                }

                Claims[OpenIdConnectConstants.Claims.Email] = value;
            }
        }

        /// <summary>
        /// Gets or sets the value used for the "email_verified" claim.
        /// Note: this value should only be populated if the "email"
        /// scope was requested and accepted by the user agent.
        /// </summary>
        public bool? EmailVerified {
            get { return (bool?) Claims[OpenIdConnectConstants.Claims.EmailVerified]; }
            set {
                if (value == null) {
                    Claims.Remove(OpenIdConnectConstants.Claims.EmailVerified);

                    return;
                }

                Claims[OpenIdConnectConstants.Claims.EmailVerified] = value;
            }
        }

        /// <summary>
        /// Gets or sets the value used for the "family_name" claim.
        /// Note: this value should only be populated if the "profile"
        /// scope was requested and accepted by the user agent.
        /// </summary>
        public string FamilyName {
            get { return (string) Claims[OpenIdConnectConstants.Claims.FamilyName]; }
            set {
                if (value == null) {
                    Claims.Remove(OpenIdConnectConstants.Claims.FamilyName);

                    return;
                }

                Claims[OpenIdConnectConstants.Claims.FamilyName] = value;
            }
        }

        /// <summary>
        /// Gets or sets the value used for the "given_name" claim.
        /// Note: this value should only be populated if the "profile"
        /// scope was requested and accepted by the user agent.
        /// </summary>
        public string GivenName {
            get { return (string) Claims[OpenIdConnectConstants.Claims.GivenName]; }
            set {
                if (value == null) {
                    Claims.Remove(OpenIdConnectConstants.Claims.GivenName);

                    return;
                }

                Claims[OpenIdConnectConstants.Claims.GivenName] = value;
            }
        }

        /// <summary>
        /// Gets or sets the value used for the "iss" claim.
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
        /// Gets or sets the value used for the "phone_number" claim.
        /// Note: this value should only be populated if the "phone"
        /// scope was requested and accepted by the user agent.
        /// </summary>
        public string PhoneNumber {
            get { return (string) Claims[OpenIdConnectConstants.Claims.PhoneNumber]; }
            set {
                if (value == null) {
                    Claims.Remove(OpenIdConnectConstants.Claims.PhoneNumber);

                    return;
                }

                Claims[OpenIdConnectConstants.Claims.PhoneNumber] = value;
            }
        }

        /// <summary>
        /// Gets or sets the value used for the "phone_number_verified" claim.
        /// Note: this value should only be populated if the "phone"
        /// scope was requested and accepted by the user agent.
        /// </summary>
        public bool? PhoneNumberVerified {
            get { return (bool?) Claims[OpenIdConnectConstants.Claims.PhoneNumberVerified]; }
            set {
                if (value == null) {
                    Claims.Remove(OpenIdConnectConstants.Claims.PhoneNumberVerified);

                    return;
                }

                Claims[OpenIdConnectConstants.Claims.PhoneNumberVerified] = value;
            }
        }

        /// <summary>
        /// Gets or sets the value used for the "preferred_username" claim.
        /// Note: this value should only be populated if the "profile"
        /// scope was requested and accepted by the user agent.
        /// </summary>
        public string PreferredUsername {
            get { return (string) Claims[OpenIdConnectConstants.Claims.PreferredUsername]; }
            set {
                if (value == null) {
                    Claims.Remove(OpenIdConnectConstants.Claims.PreferredUsername);

                    return;
                }

                Claims[OpenIdConnectConstants.Claims.PreferredUsername] = value;
            }
        }

        /// <summary>
        /// Gets or sets the value used for the "profile" claim.
        /// Note: this value should only be populated if the "profile"
        /// scope was requested and accepted by the user agent.
        /// </summary>
        public string Profile {
            get { return (string) Claims[OpenIdConnectConstants.Claims.Profile]; }
            set {
                if (value == null) {
                    Claims.Remove(OpenIdConnectConstants.Claims.Profile);

                    return;
                }

                Claims[OpenIdConnectConstants.Claims.Profile] = value;
            }
        }

        /// <summary>
        /// Gets or sets the unique value
        /// used for the mandatory "sub" claim.
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
        /// Gets or sets the value used for the "website" claim.
        /// Note: this value should only be populated if the "profile"
        /// scope was requested and accepted by the user agent.
        /// </summary>
        public string Website {
            get { return (string) Claims[OpenIdConnectConstants.Claims.Website]; }
            set {
                if (value == null) {
                    Claims.Remove(OpenIdConnectConstants.Claims.Website);

                    return;
                }

                Claims[OpenIdConnectConstants.Claims.Website] = value;
            }
        }
    }
}
