/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.Security.Claims;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Client;
using AspNet.Security.OpenIdConnect.Primitives;
using Microsoft.Owin.Security;
using Newtonsoft.Json;
using Owin.Security.OpenIdConnect.Extensions;
using Xunit;
using static System.Net.Http.HttpMethod;

namespace Owin.Security.OpenIdConnect.Server.Tests
{
    public partial class OpenIdConnectServerHandlerTests
    {
        [Theory]
        [InlineData(nameof(Delete))]
        [InlineData(nameof(Get))]
        [InlineData(nameof(Head))]
        [InlineData(nameof(Options))]
        [InlineData(nameof(Put))]
        [InlineData(nameof(Trace))]
        public async Task InvokeRevocationEndpointAsync_UnexpectedMethodReturnsAnError(string method)
        {
            // Arrange
            var server = CreateAuthorizationServer();

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.SendAsync(method, RevocationEndpoint, new OpenIdConnectRequest());

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal("The specified HTTP method is not valid.", response.ErrorDescription);
        }

        [Theory]
        [InlineData("custom_error", null, null)]
        [InlineData("custom_error", "custom_description", null)]
        [InlineData("custom_error", "custom_description", "custom_uri")]
        [InlineData(null, "custom_description", null)]
        [InlineData(null, "custom_description", "custom_uri")]
        [InlineData(null, null, "custom_uri")]
        [InlineData(null, null, null)]
        public async Task InvokeRevocationEndpointAsync_ExtractRevocationRequest_AllowsRejectingRequest(string error, string description, string uri)
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnExtractRevocationRequest = context =>
                {
                    context.Reject(error, description, uri);

                    return Task.CompletedTask;
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
        public async Task InvokeRevocationEndpointAsync_ExtractRevocationRequest_AllowsHandlingResponse()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnExtractRevocationRequest = context =>
                {
                    context.HandleResponse();

                    context.OwinContext.Response.Headers["Content-Type"] = "application/json";

                    return context.OwinContext.Response.WriteAsync(JsonConvert.SerializeObject(new
                    {
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
        public async Task InvokeRevocationEndpointAsync_ExtractRevocationRequest_AllowsSkippingToNextMiddleware()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnExtractRevocationRequest = context =>
                {
                    context.SkipToNextMiddleware();

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(RevocationEndpoint, new OpenIdConnectRequest());

            // Assert
            Assert.Equal("Bob le Magnifique", (string) response["name"]);
        }

        [Fact]
        public async Task InvokeRevocationEndpointAsync_MissingTokenCausesAnError()
        {
            // Arrange
            var server = CreateAuthorizationServer();

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(RevocationEndpoint, new OpenIdConnectRequest
            {
                Token = null
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal("The mandatory 'token' parameter is missing.", response.ErrorDescription);
        }

        [Fact]
        public async Task InvokeRevocationEndpointAsync_MultipleClientCredentialsCauseAnError()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnExtractRevocationRequest = context =>
                {
                    context.OwinContext.Request.Headers["Authorization"] = "Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW";

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(RevocationEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                ClientSecret = "7Fjfp0ZBr1KtDRbnfVdmIw",
                Token = "2YotnFZFEjr1zCsicMWpAA"
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal("Multiple client credentials cannot be specified.", response.ErrorDescription);
        }

        [Theory]
        [InlineData("custom_error", null, null)]
        [InlineData("custom_error", "custom_description", null)]
        [InlineData("custom_error", "custom_description", "custom_uri")]
        [InlineData(null, "custom_description", null)]
        [InlineData(null, "custom_description", "custom_uri")]
        [InlineData(null, null, "custom_uri")]
        [InlineData(null, null, null)]
        public async Task InvokeRevocationEndpointAsync_ValidateRevocationRequest_AllowsRejectingRequest(string error, string description, string uri)
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnValidateRevocationRequest = context =>
                {
                    context.Reject(error, description, uri);

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(RevocationEndpoint, new OpenIdConnectRequest
            {
                Token = "2YotnFZFEjr1zCsicMWpAA"
            });

            // Assert
            Assert.Equal(error ?? OpenIdConnectConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal(description, response.ErrorDescription);
            Assert.Equal(uri, response.ErrorUri);
        }

        [Fact]
        public async Task InvokeRevocationEndpointAsync_ValidateRevocationRequest_AllowsHandlingResponse()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnValidateRevocationRequest = context =>
                {
                    context.HandleResponse();

                    context.OwinContext.Response.Headers["Content-Type"] = "application/json";

                    return context.OwinContext.Response.WriteAsync(JsonConvert.SerializeObject(new
                    {
                        name = "Bob le Magnifique"
                    }));
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(RevocationEndpoint, new OpenIdConnectRequest
            {
                Token = "2YotnFZFEjr1zCsicMWpAA"
            });

            // Assert
            Assert.Equal("Bob le Magnifique", (string) response["name"]);
        }

        [Fact]
        public async Task InvokeRevocationEndpointAsync_ValidateRevocationRequest_AllowsSkippingToNextMiddleware()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnValidateRevocationRequest = context =>
                {
                    context.SkipToNextMiddleware();

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(RevocationEndpoint, new OpenIdConnectRequest
            {
                Token = "2YotnFZFEjr1zCsicMWpAA"
            });

            // Assert
            Assert.Equal("Bob le Magnifique", (string) response["name"]);
        }

        [Fact]
        public async Task InvokeRevocationEndpointAsync_ValidateRevocationRequest_MissingClientIdCausesAnExceptionForValidatedRequests()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnValidateRevocationRequest = context =>
                {
                    context.Validate();

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act and assert
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
            {
                return client.PostAsync(RevocationEndpoint, new OpenIdConnectRequest
                {
                    ClientId = null,
                    Token = "2YotnFZFEjr1zCsicMWpAA"
                });
            });

            Assert.Equal("The request cannot be validated because no client_id " +
                         "was specified by the client application.", exception.Message);
        }

        [Fact]
        public async Task InvokeRevocationEndpointAsync_ValidateRevocationRequest_InvalidClientIdCausesAnExceptionForValidatedRequests()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnValidateRevocationRequest = context =>
                {
                    context.Validate("Contoso");

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act and assert
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
            {
                return client.PostAsync(RevocationEndpoint, new OpenIdConnectRequest
                {
                    ClientId = "Fabrikam",
                    Token = "2YotnFZFEjr1zCsicMWpAA"
                });
            });

            Assert.Equal("The request cannot be validated because a different " +
                         "client_id was specified by the client application.", exception.Message);
        }

        [Theory]
        [InlineData(OpenIdConnectConstants.TokenTypeHints.AccessToken)]
        [InlineData(OpenIdConnectConstants.TokenTypeHints.AuthorizationCode)]
        [InlineData(OpenIdConnectConstants.TokenTypeHints.IdToken)]
        [InlineData(OpenIdConnectConstants.TokenTypeHints.RefreshToken)]
        public async Task InvokeRevocationEndpointAsync_TokenIsNotDeserializedTwice(string hint)
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnDeserializeAccessToken = context =>
                {
                    Assert.False(context.Request.HasProperty(nameof(options.Provider.OnDeserializeAccessToken)));
                    context.Request.AddProperty(nameof(options.Provider.OnDeserializeAccessToken), new object());

                    return Task.CompletedTask;
                };

                options.Provider.OnDeserializeAuthorizationCode = context =>
                {
                    Assert.False(context.Request.HasProperty(nameof(options.Provider.OnDeserializeAuthorizationCode)));
                    context.Request.AddProperty(nameof(options.Provider.OnDeserializeAuthorizationCode), new object());

                    return Task.CompletedTask;
                };

                options.Provider.OnDeserializeIdentityToken = context =>
                {
                    Assert.False(context.Request.HasProperty(nameof(options.Provider.OnDeserializeIdentityToken)));
                    context.Request.AddProperty(nameof(options.Provider.OnDeserializeIdentityToken), new object());

                    return Task.CompletedTask;
                };

                options.Provider.OnDeserializeRefreshToken = context =>
                {
                    Assert.False(context.Request.HasProperty(nameof(options.Provider.OnDeserializeRefreshToken)));
                    context.Request.AddProperty(nameof(options.Provider.OnDeserializeRefreshToken), new object());

                    return Task.CompletedTask;
                };

                options.Provider.OnValidateRevocationRequest = context =>
                {
                    context.Validate("Contoso");

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(RevocationEndpoint, new OpenIdConnectRequest
            {
                Token = "SlAV32hkKG",
                TokenTypeHint = hint
            });

            // Assert
            Assert.Empty(response.GetParameters());
        }

        [Fact]
        public async Task InvokeRevocationEndpointAsync_ConfidentialTokenCausesAnErrorWhenValidationIsSkipped()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnDeserializeRefreshToken = context =>
                {
                    Assert.Equal("SlAV32hkKG", context.RefreshToken);

                    context.Ticket = new AuthenticationTicket(
                        new ClaimsIdentity(context.Options.AuthenticationType),
                        new AuthenticationProperties());

                    // Mark the refresh token as private.
                    context.Ticket.SetProperty(OpenIdConnectConstants.Properties.ConfidentialityLevel,
                                               OpenIdConnectConstants.ConfidentialityLevels.Private);

                    return Task.CompletedTask;
                };

                options.Provider.OnValidateRevocationRequest = context =>
                {
                    context.Skip();

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(RevocationEndpoint, new OpenIdConnectRequest
            {
                Token = "SlAV32hkKG",
                TokenTypeHint = OpenIdConnectConstants.TokenTypeHints.RefreshToken
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidRequest, response.Error);
        }

        [Fact]
        public async Task InvokeRevocationEndpointAsync_AuthorizationCodeCausesAnErrorWhenCallerIsNotAValidPresenter()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnDeserializeAuthorizationCode = context =>
                {
                    Assert.Equal("SlAV32hkKG", context.AuthorizationCode);

                    context.Ticket = new AuthenticationTicket(
                        new ClaimsIdentity(context.Options.AuthenticationType),
                        new AuthenticationProperties());

                    context.Ticket.SetPresenters("Contoso");

                    return Task.CompletedTask;
                };

                options.Provider.OnValidateRevocationRequest = context =>
                {
                    context.Skip();

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(RevocationEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                Token = "SlAV32hkKG",
                TokenTypeHint = OpenIdConnectConstants.TokenTypeHints.AuthorizationCode
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidRequest, response.Error);
        }

        [Fact]
        public async Task InvokeRevocationEndpointAsync_AccessTokenCausesAnErrorWhenCallerIsNotAValidAudienceOrPresenter()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnDeserializeAccessToken = context =>
                {
                    Assert.Equal("2YotnFZFEjr1zCsicMWpAA", context.AccessToken);

                    context.Ticket = new AuthenticationTicket(
                        new ClaimsIdentity(context.Options.AuthenticationType),
                        new AuthenticationProperties());

                    context.Ticket.SetAudiences("AdventureWorks");
                    context.Ticket.SetPresenters("Contoso");

                    return Task.CompletedTask;
                };

                options.Provider.OnValidateRevocationRequest = context =>
                {
                    context.Skip();

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(RevocationEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                Token = "2YotnFZFEjr1zCsicMWpAA",
                TokenTypeHint = OpenIdConnectConstants.TokenTypeHints.AccessToken
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidRequest, response.Error);
        }

        [Fact]
        public async Task InvokeRevocationEndpointAsync_IdentityTokenCausesAnErrorWhenCallerIsNotAValidAudience()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnDeserializeIdentityToken = context =>
                {
                    Assert.Equal("2YotnFZFEjr1zCsicMWpAA", context.IdentityToken);

                    context.Ticket = new AuthenticationTicket(
                        new ClaimsIdentity(context.Options.AuthenticationType),
                        new AuthenticationProperties());

                    context.Ticket.SetAudiences("AdventureWorks");

                    return Task.CompletedTask;
                };

                options.Provider.OnValidateRevocationRequest = context =>
                {
                    context.Skip();

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(RevocationEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                Token = "2YotnFZFEjr1zCsicMWpAA",
                TokenTypeHint = OpenIdConnectConstants.TokenTypeHints.IdToken
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidRequest, response.Error);
        }

        [Fact]
        public async Task InvokeRevocationEndpointAsync_RefreshTokenCausesAnErrorWhenCallerIsNotAValidPresenter()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnDeserializeRefreshToken = context =>
                {
                    Assert.Equal("8xLOxBtZp8", context.RefreshToken);

                    context.Ticket = new AuthenticationTicket(
                        new ClaimsIdentity(context.Options.AuthenticationType),
                        new AuthenticationProperties());

                    context.Ticket.SetPresenters("Contoso");

                    return Task.CompletedTask;
                };

                options.Provider.OnValidateRevocationRequest = context =>
                {
                    context.Skip();

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(RevocationEndpoint, new OpenIdConnectRequest
            {
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
        public async Task InvokeRevocationEndpointAsync_HandleRevocationRequest_AllowsRejectingRequest(string error, string description, string uri)
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnDeserializeAuthorizationCode = context =>
                {
                    Assert.Equal("2YotnFZFEjr1zCsicMWpAA", context.AuthorizationCode);

                    context.Ticket = new AuthenticationTicket(
                        new ClaimsIdentity(context.Options.AuthenticationType),
                        new AuthenticationProperties());

                    return Task.CompletedTask;
                };

                options.Provider.OnValidateRevocationRequest = context =>
                {
                    context.Skip();

                    return Task.CompletedTask;
                };

                options.Provider.OnHandleRevocationRequest = context =>
                {
                    context.Reject(error, description, uri);

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(RevocationEndpoint, new OpenIdConnectRequest
            {
                Token = "2YotnFZFEjr1zCsicMWpAA"
            });

            // Assert
            Assert.Equal(error ?? OpenIdConnectConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal(description, response.ErrorDescription);
            Assert.Equal(uri, response.ErrorUri);
        }

        [Fact]
        public async Task InvokeRevocationEndpointAsync_HandleRevocationRequest_AllowsHandlingResponse()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnDeserializeAuthorizationCode = context =>
                {
                    Assert.Equal("2YotnFZFEjr1zCsicMWpAA", context.AuthorizationCode);

                    context.Ticket = new AuthenticationTicket(
                        new ClaimsIdentity(context.Options.AuthenticationType),
                        new AuthenticationProperties());

                    return Task.CompletedTask;
                };

                options.Provider.OnValidateRevocationRequest = context =>
                {
                    context.Skip();

                    return Task.CompletedTask;
                };

                options.Provider.OnHandleRevocationRequest = context =>
                {
                    context.HandleResponse();

                    context.OwinContext.Response.Headers["Content-Type"] = "application/json";

                    return context.OwinContext.Response.WriteAsync(JsonConvert.SerializeObject(new
                    {
                        name = "Bob le Magnifique"
                    }));
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(RevocationEndpoint, new OpenIdConnectRequest
            {
                Token = "2YotnFZFEjr1zCsicMWpAA"
            });

            // Assert
            Assert.Equal("Bob le Magnifique", (string) response["name"]);
        }

        [Fact]
        public async Task InvokeRevocationEndpointAsync_HandleRevocationRequest_AllowsSkippingToNextMiddleware()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnDeserializeAuthorizationCode = context =>
                {
                    Assert.Equal("2YotnFZFEjr1zCsicMWpAA", context.AuthorizationCode);

                    context.Ticket = new AuthenticationTicket(
                        new ClaimsIdentity(context.Options.AuthenticationType),
                        new AuthenticationProperties());

                    return Task.CompletedTask;
                };

                options.Provider.OnValidateRevocationRequest = context =>
                {
                    context.Skip();

                    return Task.CompletedTask;
                };

                options.Provider.OnHandleRevocationRequest = context =>
                {
                    context.SkipToNextMiddleware();

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(RevocationEndpoint, new OpenIdConnectRequest
            {
                Token = "2YotnFZFEjr1zCsicMWpAA"
            });

            // Assert
            Assert.Equal("Bob le Magnifique", (string) response["name"]);
        }

        [Fact]
        public async Task InvokeRevocationEndpointAsync_EmptyResponseIsReturnedForRevokedToken()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnDeserializeAuthorizationCode = context =>
                {
                    Assert.Equal("2YotnFZFEjr1zCsicMWpAA", context.AuthorizationCode);

                    context.Ticket = new AuthenticationTicket(
                        new ClaimsIdentity(context.Options.AuthenticationType),
                        new AuthenticationProperties());

                    return Task.CompletedTask;
                };

                options.Provider.OnValidateRevocationRequest = context =>
                {
                    context.Validate("Contoso");

                    return Task.CompletedTask;
                };

                options.Provider.OnHandleRevocationRequest = context =>
                {
                    context.Revoked = true;

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(RevocationEndpoint, new OpenIdConnectRequest
            {
                Token = "2YotnFZFEjr1zCsicMWpAA"
            });

            // Assert
            Assert.Empty(response.GetParameters());
        }

        [Fact]
        public async Task InvokeRevocationEndpointAsync_ErrorResponseIsReturnedForNonRevokedToken()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnDeserializeAuthorizationCode = context =>
                {
                    Assert.Equal("2YotnFZFEjr1zCsicMWpAA", context.AuthorizationCode);

                    context.Ticket = new AuthenticationTicket(
                        new ClaimsIdentity(context.Options.AuthenticationType),
                        new AuthenticationProperties());

                    return Task.CompletedTask;
                };

                options.Provider.OnValidateRevocationRequest = context =>
                {
                    context.Validate("Contoso");

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(RevocationEndpoint, new OpenIdConnectRequest
            {
                Token = "2YotnFZFEjr1zCsicMWpAA"
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.UnsupportedTokenType, response.Error);
            Assert.Equal("The specified token cannot be revoked.", response.ErrorDescription);
        }

        [Fact]
        public async Task SendRevocationResponseAsync_ApplyRevocationResponse_AllowsHandlingResponse()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnDeserializeAuthorizationCode = context =>
                {
                    Assert.Equal("2YotnFZFEjr1zCsicMWpAA", context.AuthorizationCode);

                    context.Ticket = new AuthenticationTicket(
                        new ClaimsIdentity(context.Options.AuthenticationType),
                        new AuthenticationProperties());

                    return Task.CompletedTask;
                };

                options.Provider.OnValidateRevocationRequest = context =>
                {
                    context.Skip();

                    return Task.CompletedTask;
                };

                options.Provider.OnApplyRevocationResponse = context =>
                {
                    context.HandleResponse();

                    context.OwinContext.Response.Headers["Content-Type"] = "application/json";

                    return context.OwinContext.Response.WriteAsync(JsonConvert.SerializeObject(new
                    {
                        name = "Bob le Magnifique"
                    }));
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(RevocationEndpoint, new OpenIdConnectRequest
            {
                Token = "2YotnFZFEjr1zCsicMWpAA"
            });

            // Assert
            Assert.Equal("Bob le Magnifique", (string) response["name"]);
        }

        [Fact]
        public async Task SendRevocationResponseAsync_ApplyRevocationResponse_ResponseContainsCustomParameters()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnDeserializeAuthorizationCode = context =>
                {
                    Assert.Equal("2YotnFZFEjr1zCsicMWpAA", context.AuthorizationCode);

                    context.Ticket = new AuthenticationTicket(
                        new ClaimsIdentity(context.Options.AuthenticationType),
                        new AuthenticationProperties());

                    return Task.CompletedTask;
                };

                options.Provider.OnValidateRevocationRequest = context =>
                {
                    context.Skip();

                    return Task.CompletedTask;
                };

                options.Provider.OnApplyRevocationResponse = context =>
                {
                    context.Response["custom_parameter"] = "custom_value";
                    context.Response["parameter_with_multiple_values"] = new[]
                    {
                        "custom_value_1",
                        "custom_value_2"
                    };

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(RevocationEndpoint, new OpenIdConnectRequest
            {
                Token = "2YotnFZFEjr1zCsicMWpAA"
            });

            // Assert
            Assert.Equal("custom_value", (string) response["custom_parameter"]);
            Assert.Equal(new[] { "custom_value_1", "custom_value_2" }, (string[]) response["parameter_with_multiple_values"]);
        }
    }
}
