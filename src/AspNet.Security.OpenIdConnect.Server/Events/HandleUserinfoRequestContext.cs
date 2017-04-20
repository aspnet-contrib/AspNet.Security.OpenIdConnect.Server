/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using AspNet.Security.OpenIdConnect.Primitives;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Newtonsoft.Json.Linq;

namespace AspNet.Security.OpenIdConnect.Server
{
    /// <summary>
    /// Represents the context class associated with the
    /// <see cref="OpenIdConnectServerProvider.HandleUserinfoRequest"/> event.
    /// </summary>
    public class HandleUserinfoRequestContext : BaseValidatingContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="HandleUserinfoRequestContext"/> class.
        /// </summary>
        public HandleUserinfoRequestContext(
            HttpContext context,
            AuthenticationScheme scheme,
            OpenIdConnectServerOptions options,
            OpenIdConnectRequest request,
            AuthenticationTicket ticket)
            : base(context, scheme, options, request)
        {
            Ticket = ticket;
            Validate();
        }

        /// <summary>
        /// Gets the authentication ticket.
        /// </summary>
        public AuthenticationTicket Ticket { get; }

        /// <summary>
        /// Gets the additional claims returned to the client application.
        /// </summary>
        public IDictionary<string, OpenIdConnectParameter> Claims { get; } =
            new Dictionary<string, OpenIdConnectParameter>(StringComparer.Ordinal);

        /// <summary>
        /// Gets or sets the value used for the "address" claim.
        /// Note: this value should only be populated if the "address"
        /// scope was requested and accepted by the resource owner.
        /// </summary>
        public JObject Address { get; set; }

        /// <summary>
        /// Gets or sets the values used for the "aud" claim.
        /// </summary>
        public ISet<string> Audiences { get; } =
            new HashSet<string>(StringComparer.Ordinal);

        /// <summary>
        /// Gets or sets the value used for the "birthdate" claim.
        /// Note: this value should only be populated if the "profile"
        /// scope was requested and accepted by the resource owner.
        /// </summary>
        public string BirthDate { get; set; }

        /// <summary>
        /// Gets or sets the value used for the "email" claim.
        /// Note: this value should only be populated if the "email"
        /// scope was requested and accepted by the resource owner.
        /// </summary>
        public string Email { get; set; }

        /// <summary>
        /// Gets or sets the value used for the "email_verified" claim.
        /// Note: this value should only be populated if the "email"
        /// scope was requested and accepted by the resource owner.
        /// </summary>
        public bool? EmailVerified { get; set; }

        /// <summary>
        /// Gets or sets the value used for the "family_name" claim.
        /// Note: this value should only be populated if the "profile"
        /// scope was requested and accepted by the resource owner.
        /// </summary>
        public string FamilyName { get; set; }

        /// <summary>
        /// Gets or sets the value used for the "given_name" claim.
        /// Note: this value should only be populated if the "profile"
        /// scope was requested and accepted by the resource owner.
        /// </summary>
        public string GivenName { get; set; }

        /// <summary>
        /// Gets or sets the value used for the "iss" claim.
        /// </summary>
        public string Issuer { get; set; }

        /// <summary>
        /// Gets or sets the value used for the "phone_number" claim.
        /// Note: this value should only be populated if the "phone"
        /// scope was requested and accepted by the resource owner.
        /// </summary>
        public string PhoneNumber { get; set; }

        /// <summary>
        /// Gets or sets the value used for the "phone_number_verified" claim.
        /// Note: this value should only be populated if the "phone"
        /// scope was requested and accepted by the resource owner.
        /// </summary>
        public bool? PhoneNumberVerified { get; set; }

        /// <summary>
        /// Gets or sets the value used for the "preferred_username" claim.
        /// Note: this value should only be populated if the "profile"
        /// scope was requested and accepted by the resource owner.
        /// </summary>
        public string PreferredUsername { get; set; }

        /// <summary>
        /// Gets or sets the value used for the "profile" claim.
        /// Note: this value should only be populated if the "profile"
        /// scope was requested and accepted by the resource owner.
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
        /// scope was requested and accepted by the resource owner.
        /// </summary>
        public string Website { get; set; }
    }
}
