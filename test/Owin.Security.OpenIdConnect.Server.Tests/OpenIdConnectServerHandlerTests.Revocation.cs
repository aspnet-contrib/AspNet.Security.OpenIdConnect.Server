using System.Security.Claims;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Primitives;
using Microsoft.Owin.Security;
using Newtonsoft.Json;
using Owin.Security.OpenIdConnect.Extensions;
using Xunit;
using static System.Net.Http.HttpMethod;

namespace Owin.Security.OpenIdConnect.Server.Tests {
    public partial class OpenIdConnectServerHandlerTests {
        [Theory]
        [InlineData(nameof(Delete))]
        [InlineData(nameof(Get))]
        [InlineData(nameof(Head))]
        [InlineData(nameof(Options))]
        [InlineData(nameof(Put))]
        [InlineData(nameof(Trace))]
        public async Task InvokeRevocationEndpointAsync_UnexpectedMethodReturnsAnError(string method) {
            // Arrange
            var server = CreateAuthorizationServer();

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.SendAsync(method, RevocationEndpoint, new OpenIdConnectRequest());

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal("A malformed revocation request has been received: " +
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
        public async Task InvokeRevocationEndpointAsync_ExtractRevocationRequest_AllowsRejectingRequest(string error, string description, string uri) {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnExtractRevocationRequest = context => {
                    context.Reject(error, description, uri);

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(RevocationEndpoint, new OpenIdConnectRequest());

            // Assert
            Assert.Equal(error ?? OpenIdConnectConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal(description, response.ErrorDescription);
            Assert.Equal(uri, response.ErrorUri);
        }

        [Fact]
        public async Task InvokeRevocationEndpointAsync_ExtractRevocationRequest_AllowsHandlingResponse() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnExtractRevocationRequest = context => {
                    context.HandleResponse();

                    context.OwinContext.Response.Headers["Content-Type"] = "application/json";

                    return context.OwinContext.Response.WriteAsync(JsonConvert.SerializeObject(new {
                        name = "Bob le Bricoleur"
                    }));
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(RevocationEndpoint, new OpenIdConnectRequest());

            // Assert
            Assert.Equal("Bob le Bricoleur", (string) response["name"]);
        }

        [Fact]
        public async Task InvokeRevocationEndpointAsync_ExtractRevocationRequest_AllowsSkippingToNextMiddleware() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnExtractRevocationRequest = context => {
                    context.SkipToNextMiddleware();

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(RevocationEndpoint, new OpenIdConnectRequest());

            // Assert
            Assert.Equal("Bob le Magnifique", (string) response["name"]);
        }

        [Fact]
        public async Task InvokeRevocationEndpointAsync_MissingTokenCausesAnError() {
            // Arrange
            var server = CreateAuthorizationServer();

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(RevocationEndpoint, new OpenIdConnectRequest {
                Token = null
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal("A malformed revocation request has been received: a 'token' parameter " +
                         "with an access or refresh token is required.", response.ErrorDescription);
        }

        [Theory]
        [InlineData("custom_error", null, null)]
        [InlineData("custom_error", "custom_description", null)]
        [InlineData("custom_error", "custom_description", "custom_uri")]
        [InlineData(null, "custom_description", null)]
        [InlineData(null, "custom_description", "custom_uri")]
        [InlineData(null, null, "custom_uri")]
        [InlineData(null, null, null)]
        public async Task InvokeRevocationEndpointAsync_ValidateRevocationRequest_AllowsRejectingRequest(string error, string description, string uri) {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnValidateRevocationRequest = context => {
                    context.Reject(error, description, uri);

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(RevocationEndpoint, new OpenIdConnectRequest {
                Token = "2YotnFZFEjr1zCsicMWpAA"
            });

            // Assert
            Assert.Equal(error ?? OpenIdConnectConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal(description, response.ErrorDescription);
            Assert.Equal(uri, response.ErrorUri);
        }

        [Fact]
        public async Task InvokeRevocationEndpointAsync_ValidateRevocationRequest_AllowsHandlingResponse() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnValidateRevocationRequest = context => {
                    context.HandleResponse();

                    context.OwinContext.Response.Headers["Content-Type"] = "application/json";

                    return context.OwinContext.Response.WriteAsync(JsonConvert.SerializeObject(new {
                        name = "Bob le Magnifique"
                    }));
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(RevocationEndpoint, new OpenIdConnectRequest {
                Token = "2YotnFZFEjr1zCsicMWpAA"
            });

            // Assert
            Assert.Equal("Bob le Magnifique", (string) response["name"]);
        }

        [Fact]
        public async Task InvokeRevocationEndpointAsync_ValidateRevocationRequest_AllowsSkippingToNextMiddleware() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnValidateRevocationRequest = context => {
                    context.SkipToNextMiddleware();

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(RevocationEndpoint, new OpenIdConnectRequest {
                Token = "2YotnFZFEjr1zCsicMWpAA"
            });

            // Assert
            Assert.Equal("Bob le Magnifique", (string) response["name"]);
        }

        [Fact]
        public async Task InvokeRevocationEndpointAsync_MissingClientIdCausesAnErrorForValidatedRequests() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnValidateRevocationRequest = context => {
                    context.Validate();

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(RevocationEndpoint, new OpenIdConnectRequest {
                ClientId = null,
                Token = "2YotnFZFEjr1zCsicMWpAA"
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.ServerError, response.Error);
            Assert.Equal("An internal server error occurred.", response.ErrorDescription);
        }

        [Fact]
        public async Task InvokeRevocationEndpointAsync_ConfidentialTokenCausesAnErrorWhenValidationIsSkipped() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnDeserializeRefreshToken = context => {
                    Assert.Equal("SlAV32hkKG", context.RefreshToken);

                    context.Ticket = new AuthenticationTicket(
                        new ClaimsIdentity(context.Options.AuthenticationType),
                        new AuthenticationProperties());

                    // Mark the refresh token as private.
                    context.Ticket.SetProperty(OpenIdConnectConstants.Properties.ConfidentialityLevel,
                                               OpenIdConnectConstants.ConfidentialityLevels.Private);

                    return Task.FromResult(0);
                };

                options.Provider.OnValidateRevocationRequest = context => {
                    context.Skip();

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(RevocationEndpoint, new OpenIdConnectRequest {
                Token = "SlAV32hkKG",
                TokenTypeHint = OpenIdConnectConstants.TokenTypeHints.RefreshToken
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidRequest, response.Error);
        }

        [Fact]
        public async Task InvokeRevocationEndpointAsync_AuthorizationCodeCausesAnErrorWhenCallerIsNotAValidPresenter() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnDeserializeAuthorizationCode = context => {
                    Assert.Equal("SlAV32hkKG", context.AuthorizationCode);

                    context.Ticket = new AuthenticationTicket(
                        new ClaimsIdentity(context.Options.AuthenticationType),
                        new AuthenticationProperties());

                    context.Ticket.SetPresenters("Contoso");

                    return Task.FromResult(0);
                };

                options.Provider.OnValidateRevocationRequest = context => {
                    context.Skip();

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(RevocationEndpoint, new OpenIdConnectRequest {
                ClientId = "Fabrikam",
                Token = "SlAV32hkKG",
                TokenTypeHint = OpenIdConnectConstants.TokenTypeHints.AuthorizationCode
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidRequest, response.Error);
        }

        [Fact]
        public async Task InvokeRevocationEndpointAsync_AccessTokenCausesAnErrorWhenCallerIsNotAValidAudienceOrPresenter() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnDeserializeAccessToken = context => {
                    Assert.Equal("2YotnFZFEjr1zCsicMWpAA", context.AccessToken);

                    context.Ticket = new AuthenticationTicket(
                        new ClaimsIdentity(context.Options.AuthenticationType),
                        new AuthenticationProperties());

                    context.Ticket.SetAudiences("AdventureWorks");
                    context.Ticket.SetPresenters("Contoso");

                    return Task.FromResult(0);
                };

                options.Provider.OnValidateRevocationRequest = context => {
                    context.Skip();

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(RevocationEndpoint, new OpenIdConnectRequest {
                ClientId = "Fabrikam",
                Token = "2YotnFZFEjr1zCsicMWpAA",
                TokenTypeHint = OpenIdConnectConstants.TokenTypeHints.AccessToken
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidRequest, response.Error);
        }

        [Fact]
        public async Task InvokeRevocationEndpointAsync_IdentityTokenCausesAnErrorWhenCallerIsNotAValidAudience() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnDeserializeIdentityToken = context => {
                    Assert.Equal("2YotnFZFEjr1zCsicMWpAA", context.IdentityToken);

                    context.Ticket = new AuthenticationTicket(
                        new ClaimsIdentity(context.Options.AuthenticationType),
                        new AuthenticationProperties());

                    context.Ticket.SetAudiences("AdventureWorks");

                    return Task.FromResult(0);
                };

                options.Provider.OnValidateRevocationRequest = context => {
                    context.Skip();

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(RevocationEndpoint, new OpenIdConnectRequest {
                ClientId = "Fabrikam",
                Token = "2YotnFZFEjr1zCsicMWpAA",
                TokenTypeHint = OpenIdConnectConstants.TokenTypeHints.IdToken
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidRequest, response.Error);
        }

        [Fact]
        public async Task InvokeRevocationEndpointAsync_RefreshTokenCausesAnErrorWhenCallerIsNotAValidPresenter() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnDeserializeRefreshToken = context => {
                    Assert.Equal("8xLOxBtZp8", context.RefreshToken);

                    context.Ticket = new AuthenticationTicket(
                        new ClaimsIdentity(context.Options.AuthenticationType),
                        new AuthenticationProperties());

                    context.Ticket.SetPresenters("Contoso");

                    return Task.FromResult(0);
                };

                options.Provider.OnValidateRevocationRequest = context => {
                    context.Skip();

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(RevocationEndpoint, new OpenIdConnectRequest {
                ClientId = "Fabrikam",
                Token = "8xLOxBtZp8",
                TokenTypeHint = OpenIdConnectConstants.TokenTypeHints.RefreshToken
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidRequest, response.Error);
        }

        [Theory]
        [InlineData("custom_error", null, null)]
        [InlineData("custom_error", "custom_description", null)]
        [InlineData("custom_error", "custom_description", "custom_uri")]
        [InlineData(null, "custom_description", null)]
        [InlineData(null, "custom_description", "custom_uri")]
        [InlineData(null, null, "custom_uri")]
        [InlineData(null, null, null)]
        public async Task InvokeRevocationEndpointAsync_HandleRevocationRequest_AllowsRejectingRequest(string error, string description, string uri) {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnDeserializeAuthorizationCode = context => {
                    Assert.Equal("2YotnFZFEjr1zCsicMWpAA", context.AuthorizationCode);

                    context.Ticket = new AuthenticationTicket(
                        new ClaimsIdentity(context.Options.AuthenticationType),
                        new AuthenticationProperties());

                    return Task.FromResult(0);
                };

                options.Provider.OnValidateRevocationRequest = context => {
                    context.Skip();

                    return Task.FromResult(0);
                };

                options.Provider.OnHandleRevocationRequest = context => {
                    context.Reject(error, description, uri);

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(RevocationEndpoint, new OpenIdConnectRequest {
                Token = "2YotnFZFEjr1zCsicMWpAA"
            });

            // Assert
            Assert.Equal(error ?? OpenIdConnectConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal(description, response.ErrorDescription);
            Assert.Equal(uri, response.ErrorUri);
        }

        [Fact]
        public async Task InvokeRevocationEndpointAsync_HandleRevocationRequest_AllowsHandlingResponse() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnDeserializeAuthorizationCode = context => {
                    Assert.Equal("2YotnFZFEjr1zCsicMWpAA", context.AuthorizationCode);

                    context.Ticket = new AuthenticationTicket(
                        new ClaimsIdentity(context.Options.AuthenticationType),
                        new AuthenticationProperties());

                    return Task.FromResult(0);
                };

                options.Provider.OnValidateRevocationRequest = context => {
                    context.Skip();

                    return Task.FromResult(0);
                };

                options.Provider.OnHandleRevocationRequest = context => {
                    context.HandleResponse();

                    context.OwinContext.Response.Headers["Content-Type"] = "application/json";

                    return context.OwinContext.Response.WriteAsync(JsonConvert.SerializeObject(new {
                        name = "Bob le Magnifique"
                    }));
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(RevocationEndpoint, new OpenIdConnectRequest {
                Token = "2YotnFZFEjr1zCsicMWpAA"
            });

            // Assert
            Assert.Equal("Bob le Magnifique", (string) response["name"]);
        }

        [Fact]
        public async Task InvokeRevocationEndpointAsync_HandleRevocationRequest_AllowsSkippingToNextMiddleware() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnDeserializeAuthorizationCode = context => {
                    Assert.Equal("2YotnFZFEjr1zCsicMWpAA", context.AuthorizationCode);

                    context.Ticket = new AuthenticationTicket(
                        new ClaimsIdentity(context.Options.AuthenticationType),
                        new AuthenticationProperties());

                    return Task.FromResult(0);
                };

                options.Provider.OnValidateRevocationRequest = context => {
                    context.Skip();

                    return Task.FromResult(0);
                };

                options.Provider.OnHandleRevocationRequest = context => {
                    context.SkipToNextMiddleware();

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(RevocationEndpoint, new OpenIdConnectRequest {
                Token = "2YotnFZFEjr1zCsicMWpAA"
            });

            // Assert
            Assert.Equal("Bob le Magnifique", (string) response["name"]);
        }

        [Fact]
        public async Task SendRevocationResponseAsync_ApplyRevocationResponse_AllowsHandlingResponse() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnDeserializeAuthorizationCode = context => {
                    Assert.Equal("2YotnFZFEjr1zCsicMWpAA", context.AuthorizationCode);

                    context.Ticket = new AuthenticationTicket(
                        new ClaimsIdentity(context.Options.AuthenticationType),
                        new AuthenticationProperties());

                    return Task.FromResult(0);
                };

                options.Provider.OnValidateRevocationRequest = context => {
                    context.Skip();

                    return Task.FromResult(0);
                };

                options.Provider.OnApplyRevocationResponse = context => {
                    context.HandleResponse();

                    context.OwinContext.Response.Headers["Content-Type"] = "application/json";

                    return context.OwinContext.Response.WriteAsync(JsonConvert.SerializeObject(new {
                        name = "Bob le Magnifique"
                    }));
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(RevocationEndpoint, new OpenIdConnectRequest {
                Token = "2YotnFZFEjr1zCsicMWpAA"
            });

            // Assert
            Assert.Equal("Bob le Magnifique", (string) response["name"]);
        }

        [Fact]
        public async Task SendRevocationResponseAsync_ApplyRevocationResponse_ResponseContainsCustomParameters() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnDeserializeAuthorizationCode = context => {
                    Assert.Equal("2YotnFZFEjr1zCsicMWpAA", context.AuthorizationCode);

                    context.Ticket = new AuthenticationTicket(
                        new ClaimsIdentity(context.Options.AuthenticationType),
                        new AuthenticationProperties());

                    return Task.FromResult(0);
                };

                options.Provider.OnValidateRevocationRequest = context => {
                    context.Skip();

                    return Task.FromResult(0);
                };

                options.Provider.OnApplyRevocationResponse = context => {
                    context.Response["custom_parameter"] = "custom_value";

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(RevocationEndpoint, new OpenIdConnectRequest {
                Token = "2YotnFZFEjr1zCsicMWpAA"
            });

            // Assert
            Assert.Equal("custom_value", (string) response["custom_parameter"]);
        }
    }
}
