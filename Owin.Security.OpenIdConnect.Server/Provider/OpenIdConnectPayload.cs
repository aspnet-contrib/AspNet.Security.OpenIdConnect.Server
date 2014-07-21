using System.Collections.Generic;

namespace Microsoft.Owin.Security.OpenIdConnect.Server {
    public class OpenIdConnectPayload : Dictionary<string, string> {
        public OpenIdConnectPayload()
            : base() {
        }

        public OpenIdConnectPayload(int capacity)
            : base(capacity) {
        }
    }
}
