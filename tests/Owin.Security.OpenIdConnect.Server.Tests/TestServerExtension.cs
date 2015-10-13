using System;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Protocols;
using Microsoft.Owin.Testing;

namespace Owin.Security.OpenIdConnect.Server.Tests {
    internal static class TestServerExtension {
        public static Task<HttpResponseMessage> SendMessageAsync(this TestServer server, OpenIdConnectMessage message, HttpMethod overrideMethod = null) {
            if (server == null)
                throw new ArgumentNullException(nameof(server));

            if (message == null)
                throw new ArgumentNullException(nameof(message));

            return server.HttpClient.SendAsync(message.ToHttpRequestMessage(overrideMethod));
        }

        public static void UseTestCertificate(this OpenIdConnectServerOptions options) {
            if (options == null)
                throw new ArgumentNullException(nameof(options));

            options.UseCertificate(
                assembly: typeof(TestServerExtension).Assembly,
                resource: "Owin.Security.OpenIdConnect.Server.Tests.Certificate.pfx",
                password: "Owin.Security.OpenIdConnect.Server");
        }
    }
}