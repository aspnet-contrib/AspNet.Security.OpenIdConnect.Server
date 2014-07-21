using System;

namespace Microsoft.Owin.Security.OpenIdConnect.Server.Messages {
    public class FormPostEndpointRequest {
        public FormPostEndpointRequest(string redirectUri, OpenIdConnectPayload payload) {
            if (String.IsNullOrWhiteSpace(redirectUri)) {
                throw new ArgumentException("redirectUri");
            }

            if (payload == null) {
                throw new ArgumentNullException("payload");
            }

            RedirectUri = redirectUri;
            Payload = payload;
        }

        public OpenIdConnectPayload Payload { get; private set; }
        public string RedirectUri { get; private set; }
    }
}
