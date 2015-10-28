/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System.Collections.Generic;
using Microsoft.AspNet.Authentication;
using Microsoft.AspNet.Http;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Newtonsoft.Json.Linq;

namespace AspNet.Security.OpenIdConnect.Server {
    /// <summary>
    /// An event raised after the Authorization Server has processed the request, but before it is passed on to the web application.
    /// Calling RequestCompleted will prevent the request from passing on to the web application.
    /// </summary>
    public sealed class ProfileEndpointContext : BaseControlContext {
        /// <summary>
        /// Creates an instance of this context
        /// </summary>
        internal ProfileEndpointContext(
            HttpContext context,
            OpenIdConnectServerOptions options,
            OpenIdConnectMessage request,
            AuthenticationTicket ticket)
            : base(context) {
            Options = options;
            AuthenticationTicket = ticket;
            Request = request;
        }

        /// <summary>
        /// Gets the options used by the OpenID Connect server.
        /// </summary>
        public OpenIdConnectServerOptions Options { get; }

        /// <summary>
        /// Gets the userinfo request.
        /// </summary>
        public new OpenIdConnectMessage Request { get; }

        /// <summary>
        /// Gets the list of claims returned to the client application.
        /// </summary>
        public IDictionary<string, JToken> Claims { get; } = new Dictionary<string, JToken>();

        /// <summary>
        /// Gets or sets the value used for the "address" claim.
        /// Note: this value should only be populated if the "address"
        /// scope was requested and accepted by the user agent.
        /// </summary>
        public JObject Address { get; set; }

        /// <summary>
        /// Gets or sets the value used for the "aud" claim.
        /// </summary>
        public string Audience { get; set; }

        /// <summary>
        /// Gets or sets the value used for the "birthdate" claim.
        /// Note: this value should only be populated if the "profile"
        /// scope was requested and accepted by the user agent.
        /// </summary>
        public string BirthDate { get; set; }

        /// <summary>
        /// Gets or sets the value used for the "email" claim.
        /// Note: this value should only be populated if the "email"
        /// scope was requested and accepted by the user agent.
        /// </summary>
        public string Email { get; set; }

        /// <summary>
        /// Gets or sets the value used for the "email_verified" claim.
        /// Note: this value should only be populated if the "email"
        /// scope was requested and accepted by the user agent.
        /// </summary>
        public bool? EmailVerified { get; set; }

        /// <summary>
        /// Gets or sets the value used for the "family_name" claim.
        /// Note: this value should only be populated if the "profile"
        /// scope was requested and accepted by the user agent.
        /// </summary>
        public string FamilyName { get; set; }

        /// <summary>
        /// Gets or sets the value used for the "given_name" claim.
        /// Note: this value should only be populated if the "profile"
        /// scope was requested and accepted by the user agent.
        /// </summary>
        public string GivenName { get; set; }

        /// <summary>
        /// Gets or sets the value used for the "iss" claim.
        /// </summary>
        public string Issuer { get; set; }

        /// <summary>
        /// Gets or sets the value used for the "phone_number" claim.
        /// Note: this value should only be populated if the "phone"
        /// scope was requested and accepted by the user agent.
        /// </summary>
        public string PhoneNumber { get; set; }

        /// <summary>
        /// Gets or sets the value used for the "phone_number_verified" claim.
        /// Note: this value should only be populated if the "phone"
        /// scope was requested and accepted by the user agent.
        /// </summary>
        public bool? PhoneNumberVerified { get; set; }

        /// <summary>
        /// Gets or sets the value used for the "preferred_username" claim.
        /// Note: this value should only be populated if the "profile"
        /// scope was requested and accepted by the user agent.
        /// </summary>
        public string PreferredUsername { get; set; }

        /// <summary>
        /// Gets or sets the value used for the "profile" claim.
        /// Note: this value should only be populated if the "profile"
        /// scope was requested and accepted by the user agent.
        /// </summary>
        public string Profile { get; set; }

        /// <summary>
        /// Gets or sets the unique value 
        /// used for the mandatory "sub" claim.
        /// </summary>
        public string Subject { get; set; }

        /// <summary>
        /// Gets or sets the value used for the "website" claim.
        /// Note: this value should only be populated if the "profile"
        /// scope was requested and accepted by the user agent.
        /// </summary>
        public string Website { get; set; }
    }
}
