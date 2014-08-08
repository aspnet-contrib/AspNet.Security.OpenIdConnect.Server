using System;
using System.Collections.Generic;
using Microsoft.Owin;
using Microsoft.Owin.Security.Provider;

namespace Owin.Security.OpenIdConnect.Server {
    /// <summary>
    /// Provides context information used when sending markup for implementing 
    /// response_mode=form_post
    /// </summary>
    public class OpenIdConnectSendFormPostMarkupContext : BaseContext {
        public OpenIdConnectSendFormPostMarkupContext(
            IOwinContext context,
            IDictionary<string, string> payload,
            string redirectUri)
            : base(context) {
            if (payload == null) {
                throw new ArgumentNullException("returnParameters");
            }

            if (string.IsNullOrEmpty(redirectUri)) {
                throw new ArgumentNullException("redirectUri");
            }

            Payload = payload;
            RedirectUri = redirectUri;
        }

        /// <summary>
        /// The parameters that should be sent to the client.
        /// </summary>
        public IDictionary<string, string> Payload { get; set; }

        /// <summary>
        /// The URI the form_post should point to.
        /// </summary>
        public string RedirectUri { get; set; }
    }
}
