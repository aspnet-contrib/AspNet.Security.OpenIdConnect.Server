using System.Threading.Tasks;
using Newtonsoft.Json;
using Owin.Security.OpenIdConnect.Extensions;
using Xunit;
using static System.Net.Http.HttpMethod;

namespace Owin.Security.OpenIdConnect.Server.Tests {
    public partial class OpenIdConnectServerHandlerTests {
        [Theory]
        [InlineData(nameof(Delete))]
        [InlineData(nameof(Head))]
        [InlineData(nameof(Options))]
        [InlineData(nameof(Put))]
        [InlineData(nameof(Trace))]
        public async Task InvokeLogoutEndpointAsync_UnexpectedMethodReturnsAnError(string method) {
            // Arrange
            var server = CreateAuthorizationServer();

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.SendAsync(method, LogoutEndpoint, new OpenIdConnectRequest());

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal("A malformed logout request has been received: " +
                         "make sure to use either GET or POST.", response.ErrorDescription);
        }

        [Theory]
        [InlineData("custom_error", null, null)]
        [InlineData("custom_error", "custom_description", null)]
        [InlineData("custom_error", "custom_description", "custom_uri")]
        [InlineData(null, "custom_description", null)]
        [InlineData(null, "custom_description", "custom_uri")]
        [InlineData(null, null, "custom_uri")]
        [InlineData(null, null, null)]
        public async Task InvokeLogoutEndpointAsync_ExtractLogoutRequest_AllowsRejectingRequest(string error, string description, string uri) {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnExtractLogoutRequest = context => {
                    context.Reject(error, description, uri);

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(LogoutEndpoint, new OpenIdConnectRequest());

            // Assert
            Assert.Equal(error ?? OpenIdConnectConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal(description, response.ErrorDescription);
            Assert.Equal(uri, response.ErrorUri);
        }

        [Fact]
        public async Task InvokeLogoutEndpointAsync_ExtractLogoutRequest_AllowsHandlingResponse() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnExtractLogoutRequest = context => {
                    context.HandleResponse();

                    context.Response.Headers["Content-Type"] = "application/json";

                    return context.Response.WriteAsync(JsonConvert.SerializeObject(new {
                        name = "Bob le Bricoleur"
                    }));
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.GetAsync(LogoutEndpoint);

            // Assert
            Assert.Equal("Bob le Bricoleur", (string) response["name"]);
        }

        [Fact]
        public async Task InvokeLogoutEndpointAsync_ExtractLogoutRequest_AllowsSkippingToNextMiddleware() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnExtractLogoutRequest = context => {
                    context.SkipToNextMiddleware();

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.GetAsync(LogoutEndpoint);

            // Assert
            Assert.Equal("Bob le Magnifique", (string) response["name"]);
        }

        [Theory]
        [InlineData("custom_error", null, null)]
        [InlineData("custom_error", "custom_description", null)]
        [InlineData("custom_error", "custom_description", "custom_uri")]
        [InlineData(null, "custom_description", null)]
        [InlineData(null, "custom_description", "custom_uri")]
        [InlineData(null, null, "custom_uri")]
        [InlineData(null, null, null)]
        public async Task InvokeLogoutEndpointAsync_ValidateLogoutRequest_AllowsRejectingRequest(string error, string description, string uri) {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnValidateLogoutRequest = context => {
                    context.Reject(error, description, uri);

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(LogoutEndpoint, new OpenIdConnectRequest());

            // Assert
            Assert.Equal(error ?? OpenIdConnectConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal(description, response.ErrorDescription);
            Assert.Equal(uri, response.ErrorUri);
        }

        [Fact]
        public async Task InvokeLogoutEndpointAsync_ValidateLogoutRequest_AllowsHandlingResponse() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnValidateLogoutRequest = context => {
                    context.HandleResponse();

                    context.Response.Headers["Content-Type"] = "application/json";

                    return context.Response.WriteAsync(JsonConvert.SerializeObject(new {
                        name = "Bob le Magnifique"
                    }));
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(LogoutEndpoint, new OpenIdConnectRequest());

            // Assert
            Assert.Equal("Bob le Magnifique", (string) response["name"]);
        }

        [Fact]
        public async Task InvokeLogoutEndpointAsync_ValidateLogoutRequest_AllowsSkippingToNextMiddleware() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnValidateLogoutRequest = context => {
                    context.SkipToNextMiddleware();

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(LogoutEndpoint, new OpenIdConnectRequest());

            // Assert
            Assert.Equal("Bob le Magnifique", (string) response["name"]);
        }

        [Theory]
        [InlineData("custom_error", null, null)]
        [InlineData("custom_error", "custom_description", null)]
        [InlineData("custom_error", "custom_description", "custom_uri")]
        [InlineData(null, "custom_description", null)]
        [InlineData(null, "custom_description", "custom_uri")]
        [InlineData(null, null, "custom_uri")]
        [InlineData(null, null, null)]
        public async Task InvokeLogoutEndpointAsync_HandleLogoutRequest_AllowsRejectingRequest(string error, string description, string uri) {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnValidateLogoutRequest = context => {
                    context.Validate();

                    return Task.FromResult(0);
                };

                options.Provider.OnHandleLogoutRequest = context => {
                    context.Reject(error, description, uri);

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(LogoutEndpoint, new OpenIdConnectRequest());

            // Assert
            Assert.Equal(error ?? OpenIdConnectConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal(description, response.ErrorDescription);
            Assert.Equal(uri, response.ErrorUri);
        }

        [Fact]
        public async Task InvokeLogoutEndpointAsync_HandleLogoutRequest_AllowsHandlingResponse() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnValidateLogoutRequest = context => {
                    context.Validate();

                    return Task.FromResult(0);
                };

                options.Provider.OnHandleLogoutRequest = context => {
                    context.HandleResponse();

                    context.Response.Headers["Content-Type"] = "application/json";

                    return context.Response.WriteAsync(JsonConvert.SerializeObject(new {
                        name = "Bob le Magnifique"
                    }));
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(LogoutEndpoint, new OpenIdConnectRequest());

            // Assert
            Assert.Equal("Bob le Magnifique", (string) response["name"]);
        }

        [Fact]
        public async Task InvokeLogoutEndpointAsync_HandleLogoutRequest_AllowsSkippingToNextMiddleware() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnValidateLogoutRequest = context => {
                    context.Validate();

                    return Task.FromResult(0);
                };

                options.Provider.OnHandleLogoutRequest = context => {
                    context.SkipToNextMiddleware();

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(LogoutEndpoint, new OpenIdConnectRequest());

            // Assert
            Assert.Equal("Bob le Magnifique", (string) response["name"]);
        }

        [Fact]
        public async Task SendLogoutResponseAsync_ApplyLogoutResponse_AllowsHandlingResponse() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnValidateLogoutRequest = context => {
                    context.Validate();

                    return Task.FromResult(0);
                };

                options.Provider.OnHandleLogoutRequest = context => {
                    context.OwinContext.Authentication.SignOut(
                        OpenIdConnectServerDefaults.AuthenticationType);
                    context.HandleResponse();

                    return Task.FromResult(0);
                };

                options.Provider.OnApplyLogoutResponse = context => {
                    context.HandleResponse();

                    context.OwinContext.Response.Headers["Content-Type"] = "application/json";

                    return context.OwinContext.Response.WriteAsync(JsonConvert.SerializeObject(new {
                        name = "Bob le Magnifique"
                    }));
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(LogoutEndpoint, new OpenIdConnectRequest());

            // Assert
            Assert.Equal("Bob le Magnifique", (string) response["name"]);
        }

        [Fact]
        public async Task SendLogoutResponseAsync_ApplyLogoutResponse_ResponseContainsCustomParameters() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnValidateLogoutRequest = context => {
                    context.Validate();

                    return Task.FromResult(0);
                };

                options.Provider.OnHandleLogoutRequest = context => {
                    context.OwinContext.Authentication.SignOut(
                        OpenIdConnectServerDefaults.AuthenticationType);
                    context.HandleResponse();

                    return Task.FromResult(0);
                };

                options.Provider.OnApplyLogoutResponse = context => {
                    context.Response["custom_parameter"] = "custom_value";

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(LogoutEndpoint, new OpenIdConnectRequest {
                PostLogoutRedirectUri = "http://www.fabrikam.com/path"
            });

            // Assert
            Assert.Equal("custom_value", (string) response["custom_parameter"]);
        }
    }
}
