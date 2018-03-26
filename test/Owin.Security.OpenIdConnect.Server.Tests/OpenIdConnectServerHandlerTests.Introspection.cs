/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Client;
using AspNet.Security.OpenIdConnect.Primitives;
using Microsoft.Owin.Infrastructure;
using Microsoft.Owin.Security;
using Moq;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Owin.Security.OpenIdConnect.Extensions;
using Xunit;
using static System.Net.Http.HttpMethod;

namespace Owin.Security.OpenIdConnect.Server.Tests
{
    public partial class OpenIdConnectServerHandlerTests
    {
        [Theory]
        [InlineData(nameof(Delete))]
        [InlineData(nameof(Head))]
        [InlineData(nameof(Options))]
        [InlineData(nameof(Put))]
        [InlineData(nameof(Trace))]
        public async Task InvokeIntrospectionEndpointAsync_UnexpectedMethodReturnsAnError(string method)
        {
            // Arrange
            var server = CreateAuthorizationServer();

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.SendAsync(method, IntrospectionEndpoint, new OpenIdConnectRequest());

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
        public async Task InvokeIntrospectionEndpointAsync_ExtractIntrospectionRequest_AllowsRejectingRequest(string error, string description, string uri)
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnExtractIntrospectionRequest = context =>
                {
                    context.Reject(error, description, uri);

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(IntrospectionEndpoint, new OpenIdConnectRequest());

            // Assert
            Assert.Equal(error ?? OpenIdConnectConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal(description, response.ErrorDescription);
            Assert.Equal(uri, response.ErrorUri);
        }

        [Fact]
        public async Task InvokeIntrospectionEndpointAsync_ExtractIntrospectionRequest_AllowsHandlingResponse()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnExtractIntrospectionRequest = context =>
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
            var response = await client.GetAsync(IntrospectionEndpoint);

            // Assert
            Assert.Equal("Bob le Bricoleur", (string) response["name"]);
        }

        [Fact]
        public async Task InvokeIntrospectionEndpointAsync_ExtractIntrospectionRequest_AllowsSkippingToNextMiddleware()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnExtractIntrospectionRequest = context =>
                {
                    context.SkipToNextMiddleware();

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.GetAsync(IntrospectionEndpoint);

            // Assert
            Assert.Equal("Bob le Magnifique", (string) response["name"]);
        }

        [Fact]
        public async Task InvokeIntrospectionEndpointAsync_MissingTokenCausesAnError()
        {
            // Arrange
            var server = CreateAuthorizationServer();

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(IntrospectionEndpoint, new OpenIdConnectRequest
            {
                Token = null
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal("The mandatory 'token' parameter is missing.", response.ErrorDescription);
        }

        [Fact]
        public async Task InvokeIntrospectionEndpointAsync_MultipleClientCredentialsCauseAnError()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnExtractIntrospectionRequest = context =>
                {
                    context.OwinContext.Request.Headers["Authorization"] = "Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW";

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(IntrospectionEndpoint, new OpenIdConnectRequest
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
        public async Task InvokeIntrospectionEndpointAsync_ValidateIntrospectionRequest_AllowsRejectingRequest(string error, string description, string uri)
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnValidateIntrospectionRequest = context =>
                {
                    context.Reject(error, description, uri);

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(IntrospectionEndpoint, new OpenIdConnectRequest
            {
                Token = "2YotnFZFEjr1zCsicMWpAA"
            });

            // Assert
            Assert.Equal(error ?? OpenIdConnectConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal(description, response.ErrorDescription);
            Assert.Equal(uri, response.ErrorUri);
        }

        [Fact]
        public async Task InvokeIntrospectionEndpointAsync_ValidateIntrospectionRequest_AllowsHandlingResponse()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnValidateIntrospectionRequest = context =>
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
            var response = await client.PostAsync(IntrospectionEndpoint, new OpenIdConnectRequest
            {
                Token = "2YotnFZFEjr1zCsicMWpAA"
            });

            // Assert
            Assert.Equal("Bob le Magnifique", (string) response["name"]);
        }

        [Fact]
        public async Task InvokeIntrospectionEndpointAsync_ValidateIntrospectionRequest_AllowsSkippingToNextMiddleware()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnValidateIntrospectionRequest = context =>
                {
                    context.SkipToNextMiddleware();

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(IntrospectionEndpoint, new OpenIdConnectRequest
            {
                Token = "2YotnFZFEjr1zCsicMWpAA"
            });

            // Assert
            Assert.Equal("Bob le Magnifique", (string) response["name"]);
        }

        [Fact]
        public async Task InvokeIntrospectionEndpointAsync_ValidateIntrospectionRequest_MissingClientIdCausesAnExceptionForValidatedRequests()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnValidateIntrospectionRequest = context =>
                {
                    context.Validate();

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act and assert
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
            {
                return client.PostAsync(IntrospectionEndpoint, new OpenIdConnectRequest
                {
                    ClientId = null,
                    Token = "2YotnFZFEjr1zCsicMWpAA"
                });
            });

            Assert.Equal("The request cannot be validated because no client_id " +
                         "was specified by the client application.", exception.Message);
        }

        [Fact]
        public async Task InvokeIntrospectionEndpointAsync_ValidateIntrospectionRequest_InvalidClientIdCausesAnExceptionForValidatedRequests()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnValidateIntrospectionRequest = context =>
                {
                    context.Validate("Contoso");

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act and assert
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
            {
                return client.PostAsync(IntrospectionEndpoint, new OpenIdConnectRequest
                {
                    ClientId = "Fabrikam",
                    Token = "2YotnFZFEjr1zCsicMWpAA"
                });
            });

            Assert.Equal("The request cannot be validated because a different " +
                         "client_id was specified by the client application.", exception.Message);
        }

        [Fact]
        public async Task InvokeIntrospectionEndpointAsync_InvalidTokenCausesAnError()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnValidateIntrospectionRequest = context =>
                {
                    context.Skip();

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(IntrospectionEndpoint, new OpenIdConnectRequest
            {
                Token = "SlAV32hkKG"
            });

            // Assert
            Assert.False((bool) response[OpenIdConnectConstants.Parameters.Active]);
        }

        [Theory]
        [InlineData(OpenIdConnectConstants.TokenTypeHints.AccessToken)]
        [InlineData(OpenIdConnectConstants.TokenTypeHints.AuthorizationCode)]
        [InlineData(OpenIdConnectConstants.TokenTypeHints.IdToken)]
        [InlineData(OpenIdConnectConstants.TokenTypeHints.RefreshToken)]
        public async Task InvokeIntrospectionEndpointAsync_TokenIsNotDeserializedTwice(string hint)
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

                options.Provider.OnValidateIntrospectionRequest = context =>
                {
                    context.Skip();

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(IntrospectionEndpoint, new OpenIdConnectRequest
            {
                Token = "SlAV32hkKG",
                TokenTypeHint = hint
            });

            // Assert
            Assert.False((bool) response[OpenIdConnectConstants.Parameters.Active]);
        }

        [Fact]
        public async Task InvokeIntrospectionEndpointAsync_ConfidentialTokenCausesAnErrorWhenValidationIsSkipped()
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

                options.Provider.OnValidateIntrospectionRequest = context =>
                {
                    context.Skip();

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(IntrospectionEndpoint, new OpenIdConnectRequest
            {
                Token = "SlAV32hkKG",
                TokenTypeHint = OpenIdConnectConstants.TokenTypeHints.RefreshToken
            });

            // Assert
            Assert.False((bool) response[OpenIdConnectConstants.Parameters.Active]);
        }

        [Fact]
        public async Task InvokeIntrospectionEndpointAsync_ExpiredTokenCausesAnError()
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

                    context.Ticket.Properties.ExpiresUtc = context.Options.SystemClock.UtcNow - TimeSpan.FromDays(1);

                    return Task.CompletedTask;
                };

                options.Provider.OnValidateIntrospectionRequest = context =>
                {
                    context.Skip();

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(IntrospectionEndpoint, new OpenIdConnectRequest
            {
                Token = "SlAV32hkKG",
                TokenTypeHint = OpenIdConnectConstants.TokenTypeHints.RefreshToken
            });

            // Assert
            Assert.False((bool) response[OpenIdConnectConstants.Parameters.Active]);
        }

        [Fact]
        public async Task InvokeIntrospectionEndpointAsync_AuthorizationCodeCausesAnErrorWhenCallerIsNotAValidPresenter()
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

                options.Provider.OnValidateIntrospectionRequest = context =>
                {
                    context.Skip();

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(IntrospectionEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                Token = "SlAV32hkKG",
                TokenTypeHint = OpenIdConnectConstants.TokenTypeHints.AuthorizationCode
            });

            // Assert
            Assert.False((bool) response[OpenIdConnectConstants.Parameters.Active]);
        }

        [Fact]
        public async Task InvokeIntrospectionEndpointAsync_AccessTokenCausesAnErrorWhenCallerIsNotAValidAudienceOrPresenter()
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

                options.Provider.OnValidateIntrospectionRequest = context =>
                {
                    context.Skip();

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(IntrospectionEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                Token = "2YotnFZFEjr1zCsicMWpAA",
                TokenTypeHint = OpenIdConnectConstants.TokenTypeHints.AccessToken
            });

            // Assert
            Assert.False((bool) response[OpenIdConnectConstants.Parameters.Active]);
        }

        [Fact]
        public async Task InvokeIntrospectionEndpointAsync_IdentityTokenCausesAnErrorWhenCallerIsNotAValidAudience()
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

                options.Provider.OnValidateIntrospectionRequest = context =>
                {
                    context.Skip();

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(IntrospectionEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                Token = "2YotnFZFEjr1zCsicMWpAA",
                TokenTypeHint = OpenIdConnectConstants.TokenTypeHints.IdToken
            });

            // Assert
            Assert.False((bool) response[OpenIdConnectConstants.Parameters.Active]);
        }

        [Fact]
        public async Task InvokeIntrospectionEndpointAsync_RefreshTokenCausesAnErrorWhenCallerIsNotAValidPresenter()
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

                options.Provider.OnValidateIntrospectionRequest = context =>
                {
                    context.Skip();

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(IntrospectionEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                Token = "8xLOxBtZp8",
                TokenTypeHint = OpenIdConnectConstants.TokenTypeHints.RefreshToken
            });

            // Assert
            Assert.False((bool) response[OpenIdConnectConstants.Parameters.Active]);
        }

        [Fact]
        public async Task InvokeIntrospectionEndpointAsync_BasicClaimsAreCorrectlyReturned()
        {
            // Arrange
            var clock = new Mock<ISystemClock>();
            clock.SetupGet(mock => mock.UtcNow)
                 .Returns(new DateTimeOffset(2016, 1, 1, 0, 0, 0, TimeSpan.Zero));

            var server = CreateAuthorizationServer(options =>
            {
                options.SystemClock = clock.Object;

                options.Provider.OnDeserializeAccessToken = context =>
                {
                    Assert.Equal("2YotnFZFEjr1zCsicMWpAA", context.AccessToken);

                    var identity = new ClaimsIdentity(context.Options.AuthenticationType);
                    identity.AddClaim(OpenIdConnectConstants.Claims.Subject, "Bob le Magnifique");

                    context.Ticket = new AuthenticationTicket(identity, new AuthenticationProperties());
                    context.Ticket.SetAudiences("Fabrikam");
                    context.Ticket.SetPresenters("Contoso", "AdventureWorks Cycles");
                    context.Ticket.SetTokenId("66B65AED-4033-4E9C-B975-A8CA7FB6FA79");

                    context.Ticket.Properties.IssuedUtc = new DateTimeOffset(2016, 1, 1, 0, 0, 0, TimeSpan.Zero);
                    context.Ticket.Properties.ExpiresUtc = new DateTimeOffset(2017, 1, 1, 0, 0, 0, TimeSpan.Zero);

                    return Task.CompletedTask;
                };

                options.Provider.OnValidateIntrospectionRequest = context =>
                {
                    context.Skip();

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(IntrospectionEndpoint, new OpenIdConnectRequest
            {
                Token = "2YotnFZFEjr1zCsicMWpAA",
                TokenTypeHint = OpenIdConnectConstants.TokenTypeHints.AccessToken
            });

            // Assert
            Assert.Equal(11, response.GetParameters().Count());
            Assert.True((bool) response[OpenIdConnectConstants.Claims.Active]);
            Assert.Equal("66B65AED-4033-4E9C-B975-A8CA7FB6FA79", (string) response[OpenIdConnectConstants.Claims.JwtId]);
            Assert.Equal(OpenIdConnectConstants.TokenTypes.Bearer, (string) response[OpenIdConnectConstants.Claims.TokenType]);
            Assert.Equal(OpenIdConnectConstants.TokenUsages.AccessToken, (string) response[OpenIdConnectConstants.Claims.TokenUsage]);
            Assert.Equal(server.BaseAddress.AbsoluteUri, (string) response[OpenIdConnectConstants.Claims.Issuer]);
            Assert.Equal("Bob le Magnifique", (string) response[OpenIdConnectConstants.Claims.Subject]);
            Assert.Equal(1451606400, (long) response[OpenIdConnectConstants.Claims.IssuedAt]);
            Assert.Equal(1451606400, (long) response[OpenIdConnectConstants.Claims.NotBefore]);
            Assert.Equal(1483228800, (long) response[OpenIdConnectConstants.Claims.ExpiresAt]);
            Assert.Equal("Fabrikam", (string) response[OpenIdConnectConstants.Claims.Audience]);
            Assert.Equal("Contoso", (string) response[OpenIdConnectConstants.Claims.ClientId]);
        }

        [Fact]
        public async Task InvokeIntrospectionEndpointAsync_NonBasicAuthorizationCodeClaimsAreNotReturned()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnDeserializeAuthorizationCode = context =>
                {
                    Assert.Equal("2YotnFZFEjr1zCsicMWpAA", context.AuthorizationCode);

                    var identity = new ClaimsIdentity(context.Options.AuthenticationType);
                    identity.AddClaim(OpenIdConnectConstants.Claims.Username, "Bob");
                    identity.AddClaim("custom_claim", "secret_value");

                    context.Ticket = new AuthenticationTicket(identity, new AuthenticationProperties());

                    return Task.CompletedTask;
                };

                options.Provider.OnValidateIntrospectionRequest = context =>
                {
                    context.Validate();

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(IntrospectionEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                ClientSecret = "7Fjfp0ZBr1KtDRbnfVdmIw",
                Token = "2YotnFZFEjr1zCsicMWpAA",
                TokenTypeHint = OpenIdConnectConstants.TokenTypeHints.AuthorizationCode
            });

            // Assert
            Assert.Null(response["custom_claim"]);
            Assert.Null(response[OpenIdConnectConstants.Claims.Username]);
        }

        [Fact]
        public async Task InvokeIntrospectionEndpointAsync_NonBasicRefreshTokenClaimsAreNotReturned()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnDeserializeRefreshToken = context =>
                {
                    Assert.Equal("2YotnFZFEjr1zCsicMWpAA", context.RefreshToken);

                    var identity = new ClaimsIdentity(context.Options.AuthenticationType);
                    identity.AddClaim(OpenIdConnectConstants.Claims.Username, "Bob");
                    identity.AddClaim("custom_claim", "secret_value");

                    context.Ticket = new AuthenticationTicket(identity, new AuthenticationProperties());

                    return Task.CompletedTask;
                };

                options.Provider.OnValidateIntrospectionRequest = context =>
                {
                    context.Validate();

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(IntrospectionEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                ClientSecret = "7Fjfp0ZBr1KtDRbnfVdmIw",
                Token = "2YotnFZFEjr1zCsicMWpAA",
                TokenTypeHint = OpenIdConnectConstants.TokenTypeHints.RefreshToken
            });

            // Assert
            Assert.Null(response["custom_claim"]);
            Assert.Null(response[OpenIdConnectConstants.Claims.Username]);
        }

        [Fact]
        public async Task InvokeIntrospectionEndpointAsync_NonBasicAccessTokenClaimsAreNotReturnedWhenValidationIsSkipped()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnDeserializeAccessToken = context =>
                {
                    Assert.Equal("2YotnFZFEjr1zCsicMWpAA", context.AccessToken);

                    var identity = new ClaimsIdentity(context.Options.AuthenticationType);
                    identity.AddClaim(OpenIdConnectConstants.Claims.Username, "Bob");
                    identity.AddClaim("custom_claim", "secret_value");

                    context.Ticket = new AuthenticationTicket(identity, new AuthenticationProperties());
                    context.Ticket.SetAudiences("Contoso");
                    context.Ticket.SetPresenters("Contoso", "AdventureWorks Cycles");
                    context.Ticket.SetScopes(OpenIdConnectConstants.Scopes.OpenId,
                                             OpenIdConnectConstants.Scopes.Profile);

                    return Task.CompletedTask;
                };

                options.Provider.OnValidateIntrospectionRequest = context =>
                {
                    context.Skip();

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(IntrospectionEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                Token = "2YotnFZFEjr1zCsicMWpAA",
                TokenTypeHint = OpenIdConnectConstants.TokenTypeHints.AccessToken
            });

            // Assert
            Assert.Null(response["custom_claim"]);
            Assert.Null(response[OpenIdConnectConstants.Claims.Username]);
            Assert.Null(response[OpenIdConnectConstants.Claims.Scope]);
        }

        [Fact]
        public async Task InvokeIntrospectionEndpointAsync_NonBasicIdentityTokenClaimsAreNotReturnedWhenValidationIsSkipped()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnDeserializeIdentityToken = context =>
                {
                    Assert.Equal("2YotnFZFEjr1zCsicMWpAA", context.IdentityToken);

                    var identity = new ClaimsIdentity(context.Options.AuthenticationType);
                    identity.AddClaim(OpenIdConnectConstants.Claims.Username, "Bob");
                    identity.AddClaim("custom_claim", "secret_value");

                    context.Ticket = new AuthenticationTicket(identity, new AuthenticationProperties());
                    context.Ticket.SetAudiences("Fabrikam");

                    return Task.CompletedTask;
                };

                options.Provider.OnValidateIntrospectionRequest = context =>
                {
                    context.Skip();

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(IntrospectionEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                Token = "2YotnFZFEjr1zCsicMWpAA",
                TokenTypeHint = OpenIdConnectConstants.TokenTypeHints.IdToken
            });

            // Assert
            Assert.Null(response["custom_claim"]);
            Assert.Null(response[OpenIdConnectConstants.Claims.Username]);
        }

        [Fact]
        public async Task InvokeIntrospectionEndpointAsync_NonBasicAccessTokenClaimsAreReturnedToTrustedAudiences()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnDeserializeAccessToken = context =>
                {
                    Assert.Equal("2YotnFZFEjr1zCsicMWpAA", context.AccessToken);

                    var identity = new ClaimsIdentity(context.Options.AuthenticationType);
                    identity.AddClaim(OpenIdConnectConstants.Claims.Username, "Bob");
                    identity.AddClaim("custom_claim", "secret_value");

                    context.Ticket = new AuthenticationTicket(identity, new AuthenticationProperties());
                    context.Ticket.SetAudiences("Fabrikam");
                    context.Ticket.SetPresenters("Contoso", "AdventureWorks Cycles");
                    context.Ticket.SetScopes(OpenIdConnectConstants.Scopes.OpenId,
                                             OpenIdConnectConstants.Scopes.Profile);

                    return Task.CompletedTask;
                };

                options.Provider.OnValidateIntrospectionRequest = context =>
                {
                    context.Validate();

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(IntrospectionEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                ClientSecret = "7Fjfp0ZBr1KtDRbnfVdmIw",
                Token = "2YotnFZFEjr1zCsicMWpAA",
                TokenTypeHint = OpenIdConnectConstants.TokenTypeHints.AccessToken
            });

            // Assert
            Assert.Equal("secret_value", (string) response["custom_claim"]);
            Assert.Equal("Bob", (string) response[OpenIdConnectConstants.Claims.Username]);
            Assert.Equal("openid profile", (string) response[OpenIdConnectConstants.Claims.Scope]);
        }

        [Fact]
        public async Task InvokeIntrospectionEndpointAsync_NonBasicIdentityClaimsAreReturnedToTrustedAudiences()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnDeserializeIdentityToken = context =>
                {
                    Assert.Equal("2YotnFZFEjr1zCsicMWpAA", context.IdentityToken);

                    var identity = new ClaimsIdentity(context.Options.AuthenticationType);
                    identity.AddClaim(OpenIdConnectConstants.Claims.Username, "Bob");
                    identity.AddClaim("custom_claim", "secret_value");

                    context.Ticket = new AuthenticationTicket(identity, new AuthenticationProperties());
                    context.Ticket.SetAudiences("Fabrikam");

                    return Task.CompletedTask;
                };

                options.Provider.OnValidateIntrospectionRequest = context =>
                {
                    context.Validate();

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(IntrospectionEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                ClientSecret = "7Fjfp0ZBr1KtDRbnfVdmIw",
                Token = "2YotnFZFEjr1zCsicMWpAA",
                TokenTypeHint = OpenIdConnectConstants.TokenTypeHints.IdToken
            });

            // Assert
            Assert.Equal("secret_value", (string) response["custom_claim"]);
            Assert.Equal("Bob", (string) response[OpenIdConnectConstants.Claims.Username]);
        }

        [Fact]
        public async Task InvokeIntrospectionEndpointAsync_ClaimValueTypesAreHonored()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnDeserializeAccessToken = context =>
                {
                    Assert.Equal("2YotnFZFEjr1zCsicMWpAA", context.AccessToken);

                    var identity = new ClaimsIdentity(context.Options.AuthenticationType);
                    identity.AddClaim(new Claim("boolean_claim", "true", ClaimValueTypes.Boolean));
                    identity.AddClaim(new Claim("integer_claim", "42", ClaimValueTypes.Integer));
                    identity.AddClaim(new Claim("array_claim", @"[""Contoso"",""Fabrikam""]", JsonClaimValueTypes.JsonArray));
                    identity.AddClaim(new Claim("object_claim", @"{""parameter"":""value""}", JsonClaimValueTypes.Json));

                    context.Ticket = new AuthenticationTicket(identity, new AuthenticationProperties());

                    return Task.CompletedTask;
                };

                options.Provider.OnValidateIntrospectionRequest = context =>
                {
                    context.Validate();

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(IntrospectionEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                ClientSecret = "7Fjfp0ZBr1KtDRbnfVdmIw",
                Token = "2YotnFZFEjr1zCsicMWpAA",
                TokenTypeHint = OpenIdConnectConstants.TokenTypeHints.AccessToken
            });

            // Assert
            Assert.True((bool) response["boolean_claim"]);
            Assert.Equal(JTokenType.Boolean, ((JToken) response["boolean_claim"]).Type);
            Assert.Equal(42, (long) response["integer_claim"]);
            Assert.Equal(JTokenType.Integer, ((JToken) response["integer_claim"]).Type);
            Assert.Equal(new[] { "Contoso", "Fabrikam" }, (string[]) response["array_claim"]);
            Assert.Equal(JTokenType.Array, ((JToken) response["array_claim"]).Type);
            Assert.Equal("value", (string) response["object_claim"]?["parameter"]);
            Assert.Equal(JTokenType.Object, ((JToken) response["object_claim"]).Type);
        }

        [Fact]
        public async Task InvokeIntrospectionEndpointAsync_InvalidClaimsAreReturnedAsStrings()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnDeserializeAccessToken = context =>
                {
                    Assert.Equal("2YotnFZFEjr1zCsicMWpAA", context.AccessToken);

                    var identity = new ClaimsIdentity(context.Options.AuthenticationType);
                    identity.AddClaim(new Claim("boolean_claim", "Contoso", ClaimValueTypes.Boolean));
                    identity.AddClaim(new Claim("integer_claim", "Contoso", ClaimValueTypes.Integer));
                    identity.AddClaim(new Claim("array_claim", "Contoso", JsonClaimValueTypes.JsonArray));
                    identity.AddClaim(new Claim("object_claim", "Contoso", JsonClaimValueTypes.Json));

                    context.Ticket = new AuthenticationTicket(identity, new AuthenticationProperties());

                    return Task.CompletedTask;
                };

                options.Provider.OnValidateIntrospectionRequest = context =>
                {
                    context.Validate();

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(IntrospectionEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                ClientSecret = "7Fjfp0ZBr1KtDRbnfVdmIw",
                Token = "2YotnFZFEjr1zCsicMWpAA",
                TokenTypeHint = OpenIdConnectConstants.TokenTypeHints.AccessToken
            });

            // Assert
            Assert.Equal("Contoso", (string) response["boolean_claim"]);
            Assert.Equal(JTokenType.String, ((JToken) response["boolean_claim"]).Type);
            Assert.Equal("Contoso", (string) response["integer_claim"]);
            Assert.Equal(JTokenType.String, ((JToken) response["integer_claim"]).Type);
            Assert.Equal("Contoso", (string) response["array_claim"]);
            Assert.Equal(JTokenType.String, ((JToken) response["array_claim"]).Type);
            Assert.Equal("Contoso", (string) response["object_claim"]);
            Assert.Equal(JTokenType.String, ((JToken) response["object_claim"]).Type);
        }

        [Fact]
        public async Task InvokeIntrospectionEndpointAsync_MultipleClaimsAreReturnedAsArrays()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnDeserializeAccessToken = context =>
                {
                    Assert.Equal("2YotnFZFEjr1zCsicMWpAA", context.AccessToken);

                    var identity = new ClaimsIdentity(context.Options.AuthenticationType);
                    identity.AddClaim(new Claim("boolean_claim", "true", ClaimValueTypes.Boolean));
                    identity.AddClaim(new Claim("boolean_claim", "false", ClaimValueTypes.Boolean));

                    identity.AddClaim(new Claim("integer_claim", "42", ClaimValueTypes.Integer));
                    identity.AddClaim(new Claim("integer_claim", "43", ClaimValueTypes.Integer));

                    identity.AddClaim(new Claim("array_claim", @"[""Contoso"",""Fabrikam""]", JsonClaimValueTypes.JsonArray));
                    identity.AddClaim(new Claim("array_claim", @"[""Microsoft"",""Google""]", JsonClaimValueTypes.JsonArray));

                    identity.AddClaim(new Claim("object_claim", @"{""parameter_1"":""value-1""}", JsonClaimValueTypes.Json));
                    identity.AddClaim(new Claim("object_claim", @"{""parameter_2"":""value-2""}", JsonClaimValueTypes.Json));

                    context.Ticket = new AuthenticationTicket(identity, new AuthenticationProperties());

                    return Task.CompletedTask;
                };

                options.Provider.OnValidateIntrospectionRequest = context =>
                {
                    context.Validate();

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(IntrospectionEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                ClientSecret = "7Fjfp0ZBr1KtDRbnfVdmIw",
                Token = "2YotnFZFEjr1zCsicMWpAA",
                TokenTypeHint = OpenIdConnectConstants.TokenTypeHints.AccessToken
            });

            // Assert
            Assert.Equal(new JArray(new[] { true, false }), (JArray) response["boolean_claim"]);
            Assert.Equal(JTokenType.Array, ((JToken) response["boolean_claim"]).Type);
            Assert.Equal(new JArray(new[] { 42, 43 }), (JArray) response["integer_claim"]);
            Assert.Equal(JTokenType.Array, ((JToken) response["integer_claim"]).Type);
            Assert.Equal(new JArray(new[] {
                new JArray(new[] { "Contoso", "Fabrikam" }),
                new JArray(new[] { "Microsoft", "Google" }) }), (JArray) response["array_claim"]);
            Assert.Equal(JTokenType.Array, ((JToken) response["array_claim"]).Type);
            Assert.Equal(new JArray(new[] {
                JObject.FromObject(new { parameter_1 = "value-1" }),
                JObject.FromObject(new { parameter_2 = "value-2" }) }), (JArray) response["object_claim"]);
            Assert.Equal(JTokenType.Array, ((JToken) response["object_claim"]).Type);
        }

        [Theory]
        [InlineData("custom_error", null, null)]
        [InlineData("custom_error", "custom_description", null)]
        [InlineData("custom_error", "custom_description", "custom_uri")]
        [InlineData(null, "custom_description", null)]
        [InlineData(null, "custom_description", "custom_uri")]
        [InlineData(null, null, "custom_uri")]
        [InlineData(null, null, null)]
        public async Task InvokeIntrospectionEndpointAsync_HandleIntrospectionRequest_AllowsRejectingRequest(string error, string description, string uri)
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

                    return Task.CompletedTask;
                };

                options.Provider.OnValidateIntrospectionRequest = context =>
                {
                    context.Skip();

                    return Task.CompletedTask;
                };

                options.Provider.OnHandleIntrospectionRequest = context =>
                {
                    context.Reject(error, description, uri);

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(IntrospectionEndpoint, new OpenIdConnectRequest
            {
                Token = "SlAV32hkKG"
            });

            // Assert
            Assert.Equal(error ?? OpenIdConnectConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal(description, response.ErrorDescription);
            Assert.Equal(uri, response.ErrorUri);
        }

        [Fact]
        public async Task InvokeIntrospectionEndpointAsync_HandleIntrospectionRequest_AllowsHandlingResponse()
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

                    return Task.CompletedTask;
                };

                options.Provider.OnValidateIntrospectionRequest = context =>
                {
                    context.Skip();

                    return Task.CompletedTask;
                };

                options.Provider.OnHandleIntrospectionRequest = context =>
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
            var response = await client.PostAsync(IntrospectionEndpoint, new OpenIdConnectRequest
            {
                Token = "SlAV32hkKG"
            });

            // Assert
            Assert.Equal("Bob le Magnifique", (string) response["name"]);
        }

        [Fact]
        public async Task InvokeIntrospectionEndpointAsync_HandleIntrospectionRequest_AllowsSkippingToNextMiddleware()
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

                    return Task.CompletedTask;
                };

                options.Provider.OnValidateIntrospectionRequest = context =>
                {
                    context.Skip();

                    return Task.CompletedTask;
                };

                options.Provider.OnHandleIntrospectionRequest = context =>
                {
                    context.SkipToNextMiddleware();

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(IntrospectionEndpoint, new OpenIdConnectRequest
            {
                Token = "SlAV32hkKG"
            });

            // Assert
            Assert.Equal("Bob le Magnifique", (string) response["name"]);
        }

        [Fact]
        public async Task SendIntrospectionResponseAsync_ApplyIntrospectionResponse_AllowsHandlingResponse()
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

                    return Task.CompletedTask;
                };

                options.Provider.OnValidateIntrospectionRequest = context =>
                {
                    context.Skip();

                    return Task.CompletedTask;
                };

                options.Provider.OnApplyIntrospectionResponse = context =>
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
            var response = await client.PostAsync(IntrospectionEndpoint, new OpenIdConnectRequest
            {
                Token = "SlAV32hkKG"
            });

            // Assert
            Assert.Equal("Bob le Magnifique", (string) response["name"]);
        }

        [Fact]
        public async Task SendIntrospectionResponseAsync_ApplyIntrospectionResponse_ResponseContainsCustomParameters()
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

                    return Task.CompletedTask;
                };

                options.Provider.OnValidateIntrospectionRequest = context =>
                {
                    context.Skip();

                    return Task.CompletedTask;
                };

                options.Provider.OnApplyIntrospectionResponse = context =>
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
            var response = await client.PostAsync(IntrospectionEndpoint, new OpenIdConnectRequest
            {
                Token = "SlAV32hkKG"
            });

            // Assert
            Assert.Equal("custom_value", (string) response["custom_parameter"]);
            Assert.Equal(new[] { "custom_value_1", "custom_value_2" }, (string[]) response["parameter_with_multiple_values"]);
        }
    }
}
