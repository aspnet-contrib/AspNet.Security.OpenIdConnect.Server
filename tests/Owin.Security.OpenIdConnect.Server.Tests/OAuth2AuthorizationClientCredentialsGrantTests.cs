using System.Net;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Protocols;
using Microsoft.Owin.Testing;
using Xunit;

namespace Owin.Security.OpenIdConnect.Server.Tests {
    public class OAuth2AuthorizationClientCredentialsGrantTests {
        [Fact]
        public async Task ClientCredentials_MissingCredentials_BadRequest() {

            var server = TestServer.Create(app =>
                app.UseOpenIdConnectServer(options => options.AllowInsecureHttp = true));

            var response = await server.SendMessageAsync(new OpenIdConnectMessage
            {
                RequestType = OpenIdConnectRequestType.TokenRequest,
                GrantType = "client_credentials",
                TokenEndpoint = "connect/token"
            });

            var openIdResponseMessage = await response.ReadAsOpenIdConnectMessageAsync();

            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidClient, openIdResponseMessage.Error);
        }
    }
}