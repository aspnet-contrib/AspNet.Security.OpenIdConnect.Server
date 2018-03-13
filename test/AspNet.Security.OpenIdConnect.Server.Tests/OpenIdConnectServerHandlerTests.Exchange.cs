/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Client;
using AspNet.Security.OpenIdConnect.Extensions;
using AspNet.Security.OpenIdConnect.Primitives;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Net.Http.Headers;
using Newtonsoft.Json;
using Xunit;
using static System.Net.Http.HttpMethod;

namespace AspNet.Security.OpenIdConnect.Server.Tests
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
        public async Task InvokeTokenEndpointAsync_UnexpectedMethodReturnsAnError(string method)
        {
            // Arrange
            var server = CreateAuthorizationServer();

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.SendAsync(method, TokenEndpoint, new OpenIdConnectRequest());

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
        public async Task InvokeTokenEndpointAsync_ExtractTokenRequest_AllowsRejectingRequest(string error, string description, string uri)
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnExtractTokenRequest = context =>
                {
                    context.Reject(error, description, uri);

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest());

            // Assert
            Assert.Equal(error ?? OpenIdConnectConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal(description, response.ErrorDescription);
            Assert.Equal(uri, response.ErrorUri);
        }

        [Fact]
        public async Task InvokeTokenEndpointAsync_ExtractTokenRequest_AllowsHandlingResponse()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnExtractTokenRequest = context =>
                {
                    context.HandleResponse();

                    context.HttpContext.Response.Headers[HeaderNames.ContentType] = "application/json";

                    return context.HttpContext.Response.WriteAsync(JsonConvert.SerializeObject(new
                    {
                        name = "Bob le Bricoleur"
                    }));
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest());

            // Assert
            Assert.Equal("Bob le Bricoleur", (string) response["name"]);
        }

        [Fact]
        public async Task InvokeTokenEndpointAsync_ExtractTokenRequest_AllowsSkippingHandler()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnExtractTokenRequest = context =>
                {
                    context.SkipHandler();

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest());

            // Assert
            Assert.Equal("Bob le Magnifique", (string) response["name"]);
        }

        [Fact]
        public async Task InvokeTokenEndpointAsync_MissingGrantTypeCausesAnError()
        {
            // Arrange
            var server = CreateAuthorizationServer();

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                GrantType = null
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal("The mandatory 'grant_type' parameter is missing.", response.ErrorDescription);
        }

        [Fact]
        public async Task InvokeTokenEndpointAsync_AuthorizationCodeGrantTypeCausesAnErrorWhenAuthorizationEndpointIsDisabled()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.AuthorizationEndpointPath = PathString.Empty;
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                GrantType = OpenIdConnectConstants.GrantTypes.AuthorizationCode
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.UnsupportedGrantType, response.Error);
            Assert.Equal("The authorization code grant is not allowed by this authorization server.", response.ErrorDescription);
        }

        [Fact]
        public async Task InvokeTokenEndpointAsync_MissingCodeCausesAnError()
        {
            // Arrange
            var server = CreateAuthorizationServer();

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                Code = null,
                GrantType = OpenIdConnectConstants.GrantTypes.AuthorizationCode
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal("The mandatory 'code' parameter is missing.", response.ErrorDescription);
        }

        [Fact]
        public async Task InvokeTokenEndpointAsync_MissingRefreshTokenCausesAnError()
        {
            // Arrange
            var server = CreateAuthorizationServer();

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                GrantType = OpenIdConnectConstants.GrantTypes.RefreshToken,
                RefreshToken = null
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal("The mandatory 'refresh_token' parameter is missing.", response.ErrorDescription);
        }

        [Theory]
        [InlineData(null, null)]
        [InlineData("username", null)]
        [InlineData(null, "password")]
        public async Task InvokeTokenEndpointAsync_MissingUserCredentialsCauseAnError(string username, string password)
        {
            // Arrange
            var server = CreateAuthorizationServer();

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                GrantType = OpenIdConnectConstants.GrantTypes.Password,
                Username = username,
                Password = password
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal("The mandatory 'username' and/or 'password' parameters are missing.", response.ErrorDescription);
        }

        [Fact]
        public async Task InvokeTokenEndpointAsync_MultipleClientCredentialsCauseAnError()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnExtractTokenRequest = context =>
                {
                    context.HttpContext.Request.Headers[HeaderNames.Authorization] = "Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW";

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                ClientSecret = "7Fjfp0ZBr1KtDRbnfVdmIw",
                GrantType = OpenIdConnectConstants.GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w"
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
        public async Task InvokeTokenEndpointAsync_ValidateTokenRequest_AllowsRejectingRequest(string error, string description, string uri)
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnValidateTokenRequest = context =>
                {
                    context.Reject(error, description, uri);

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                GrantType = OpenIdConnectConstants.GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w"
            });

            // Assert
            Assert.Equal(error ?? OpenIdConnectConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal(description, response.ErrorDescription);
            Assert.Equal(uri, response.ErrorUri);
        }

        [Fact]
        public async Task InvokeTokenEndpointAsync_ValidateTokenRequest_AllowsHandlingResponse()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnValidateTokenRequest = context =>
                {
                    context.HandleResponse();

                    context.HttpContext.Response.Headers[HeaderNames.ContentType] = "application/json";

                    return context.HttpContext.Response.WriteAsync(JsonConvert.SerializeObject(new
                    {
                        name = "Bob le Magnifique"
                    }));
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                GrantType = OpenIdConnectConstants.GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w"
            });

            // Assert
            Assert.Equal("Bob le Magnifique", (string) response["name"]);
        }

        [Fact]
        public async Task InvokeTokenEndpointAsync_ValidateTokenRequest_AllowsSkippingHandler()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnValidateTokenRequest = context =>
                {
                    context.SkipHandler();

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                GrantType = OpenIdConnectConstants.GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w"
            });

            // Assert
            Assert.Equal("Bob le Magnifique", (string) response["name"]);
        }

        [Fact]
        public async Task InvokeTokenEndpointAsync_ValidateTokenRequest_MissingClientIdCausesAnErrorForClientCredentialsRequests()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnValidateTokenRequest = context =>
                {
                    context.Skip();

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                Code = "SplxlOBeZQQYbYS6WxSbIA",
                GrantType = OpenIdConnectConstants.GrantTypes.ClientCredentials
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidGrant, response.Error);
            Assert.Equal("Client authentication is required when using the client credentials grant.", response.ErrorDescription);
        }

        [Fact]
        public async Task InvokeTokenEndpointAsync_ValidateTokenRequest_MissingClientIdCausesAnExceptionForValidatedRequests()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnValidateTokenRequest = context =>
                {
                    context.Validate();

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act and assert
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
            {
                return client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
                {
                    ClientId = null,
                    Code = "SplxlOBeZQQYbYS6WxSbIA",
                    GrantType = OpenIdConnectConstants.GrantTypes.AuthorizationCode
                });
            });

            Assert.Equal("The request cannot be validated because no client_id " +
                         "was specified by the client application.", exception.Message);
        }

        [Fact]
        public async Task InvokeTokenEndpointAsync_ValidateTokenRequest_InvalidClientIdCausesAnExceptionForValidatedRequests()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnValidateTokenRequest = context =>
                {
                    context.Validate("Consoto");

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act and assert
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
            {
                return client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
                {
                    ClientId = "Fabrikam",
                    Code = "SplxlOBeZQQYbYS6WxSbIA",
                    GrantType = OpenIdConnectConstants.GrantTypes.AuthorizationCode
                });
            });

            Assert.Equal("The request cannot be validated because a different " +
                         "client_id was specified by the client application.", exception.Message);
        }

        [Fact]
        public async Task InvokeTokenEndpointAsync_ValidateTokenRequest_MissingClientIdCausesAnErrorForCodeFlowRequests()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnValidateTokenRequest = context =>
                {
                    context.Skip();

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                ClientId = null,
                Code = "SplxlOBeZQQYbYS6WxSbIA",
                GrantType = OpenIdConnectConstants.GrantTypes.AuthorizationCode
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal("The mandatory 'client_id' parameter is missing.", response.ErrorDescription);
        }

        [Fact]
        public async Task InvokeTokenEndpointAsync_InvalidAuthorizationCodeCausesAnError()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnValidateTokenRequest = context =>
                {
                    context.Skip();

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                Code = "SplxlOBeZQQYbYS6WxSbIA",
                GrantType = OpenIdConnectConstants.GrantTypes.AuthorizationCode
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidGrant, response.Error);
            Assert.Equal("The specified authorization code is invalid.", response.ErrorDescription);
        }

        [Fact]
        public async Task InvokeTokenEndpointAsync_InvalidRefreshTokenCausesAnError()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnValidateTokenRequest = context =>
                {
                    context.Skip();

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                GrantType = OpenIdConnectConstants.GrantTypes.RefreshToken,
                RefreshToken = "8xLOxBtZp8"
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidGrant, response.Error);
            Assert.Equal("The specified refresh token is invalid.", response.ErrorDescription);
        }

        [Fact]
        public async Task InvokeTokenEndpointAsync_ConfidentialRefreshTokenCausesAnErrorWhenValidationIsSkipped()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnDeserializeRefreshToken = context =>
                {
                    Assert.Equal("8xLOxBtZp8", context.RefreshToken);

                    context.Ticket = new AuthenticationTicket(
                        new ClaimsPrincipal(),
                        new AuthenticationProperties(),
                        OpenIdConnectServerDefaults.AuthenticationScheme);

                    // Mark the refresh token as private.
                    context.Ticket.SetProperty(OpenIdConnectConstants.Properties.ConfidentialityLevel,
                                               OpenIdConnectConstants.ConfidentialityLevels.Private);

                    return Task.CompletedTask;
                };

                options.Provider.OnValidateTokenRequest = context =>
                {
                    context.Skip();

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                GrantType = OpenIdConnectConstants.GrantTypes.RefreshToken,
                RefreshToken = "8xLOxBtZp8"
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidGrant, response.Error);
            Assert.Equal("Client authentication is required to use the specified refresh token.", response.ErrorDescription);
        }

        [Fact]
        public async Task InvokeTokenEndpointAsync_ExpiredAuthorizationCodeCausesAnError()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnDeserializeAuthorizationCode = context =>
                {
                    Assert.Equal("SplxlOBeZQQYbYS6WxSbIA", context.AuthorizationCode);

                    context.Ticket = new AuthenticationTicket(
                        new ClaimsPrincipal(),
                        new AuthenticationProperties(),
                        OpenIdConnectServerDefaults.AuthenticationScheme);

                    context.Ticket.Properties.ExpiresUtc = context.Options.SystemClock.UtcNow - TimeSpan.FromDays(1);

                    return Task.CompletedTask;
                };

                options.Provider.OnValidateTokenRequest = context =>
                {
                    context.Skip();

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                Code = "SplxlOBeZQQYbYS6WxSbIA",
                GrantType = OpenIdConnectConstants.GrantTypes.AuthorizationCode
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidGrant, response.Error);
            Assert.Equal("The specified authorization code is no longer valid.", response.ErrorDescription);
        }

        [Fact]
        public async Task InvokeTokenEndpointAsync_ExpiredRefreshTokenCausesAnError()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnDeserializeRefreshToken = context =>
                {
                    Assert.Equal("8xLOxBtZp8", context.RefreshToken);

                    context.Ticket = new AuthenticationTicket(
                        new ClaimsPrincipal(),
                        new AuthenticationProperties(),
                        OpenIdConnectServerDefaults.AuthenticationScheme);

                    context.Ticket.Properties.ExpiresUtc = context.Options.SystemClock.UtcNow - TimeSpan.FromDays(1);

                    return Task.CompletedTask;
                };

                options.Provider.OnValidateTokenRequest = context =>
                {
                    context.Skip();

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                GrantType = OpenIdConnectConstants.GrantTypes.RefreshToken,
                RefreshToken = "8xLOxBtZp8"
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidGrant, response.Error);
            Assert.Equal("The specified refresh token is no longer valid.", response.ErrorDescription);
        }

        [Fact]
        public async Task InvokeTokenEndpointAsync_AuthorizationCodeCausesAnErrorWhenPresentersAreMissing()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnDeserializeAuthorizationCode = context =>
                {
                    Assert.Equal("SplxlOBeZQQYbYS6WxSbIA", context.AuthorizationCode);

                    context.Ticket = new AuthenticationTicket(
                        new ClaimsPrincipal(),
                        new AuthenticationProperties(),
                        OpenIdConnectServerDefaults.AuthenticationScheme);

                    context.Ticket.SetPresenters(Enumerable.Empty<string>());

                    return Task.CompletedTask;
                };

                options.Provider.OnValidateTokenRequest = context =>
                {
                    context.Skip();

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act and assert
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
            {
                return client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
                {
                    ClientId = "Fabrikam",
                    Code = "SplxlOBeZQQYbYS6WxSbIA",
                    GrantType = OpenIdConnectConstants.GrantTypes.AuthorizationCode
                });
            });

            Assert.Equal("The presenters list cannot be extracted from the authorization code.", exception.Message);
        }

        [Fact]
        public async Task InvokeTokenEndpointAsync_AuthorizationCodeCausesAnErrorWhenCallerIsNotAPresenter()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnDeserializeAuthorizationCode = context =>
                {
                    Assert.Equal("SplxlOBeZQQYbYS6WxSbIA", context.AuthorizationCode);

                    context.Ticket = new AuthenticationTicket(
                        new ClaimsPrincipal(),
                        new AuthenticationProperties(),
                        OpenIdConnectServerDefaults.AuthenticationScheme);

                    context.Ticket.SetPresenters("Contoso");

                    return Task.CompletedTask;
                };

                options.Provider.OnValidateTokenRequest = context =>
                {
                    context.Skip();

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                Code = "SplxlOBeZQQYbYS6WxSbIA",
                GrantType = OpenIdConnectConstants.GrantTypes.AuthorizationCode
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidGrant, response.Error);
            Assert.Equal("The specified authorization code cannot be used by this client application.", response.ErrorDescription);
        }

        [Fact]
        public async Task InvokeTokenEndpointAsync_RefreshTokenCausesAnErrorWhenCallerIsNotAPresenter()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnDeserializeRefreshToken = context =>
                {
                    Assert.Equal("8xLOxBtZp8", context.RefreshToken);

                    var identity = new ClaimsIdentity(OpenIdConnectServerDefaults.AuthenticationScheme);
                    identity.AddClaim(OpenIdConnectConstants.Claims.Subject, "Bob le Magnifique");

                    context.Ticket = new AuthenticationTicket(
                        new ClaimsPrincipal(identity),
                        new AuthenticationProperties(),
                        OpenIdConnectServerDefaults.AuthenticationScheme);

                    context.Ticket.SetPresenters("Contoso");

                    return Task.CompletedTask;
                };

                options.Provider.OnValidateTokenRequest = context =>
                {
                    context.Skip();

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                GrantType = OpenIdConnectConstants.GrantTypes.RefreshToken,
                RefreshToken = "8xLOxBtZp8"
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidGrant, response.Error);
            Assert.Equal("The specified refresh token cannot be used by this client application.", response.ErrorDescription);
        }

        [Fact]
        public async Task InvokeTokenEndpointAsync_AuthorizationCodeCausesAnErrorWhenRedirectUriIsMissing()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnDeserializeAuthorizationCode = context =>
                {
                    Assert.Equal("SplxlOBeZQQYbYS6WxSbIA", context.AuthorizationCode);

                    context.Ticket = new AuthenticationTicket(
                        new ClaimsPrincipal(),
                        new AuthenticationProperties(),
                        OpenIdConnectServerDefaults.AuthenticationScheme);

                    context.Ticket.SetProperty(
                        OpenIdConnectConstants.Properties.OriginalRedirectUri,
                        "http://www.fabrikam.com/callback");

                    context.Ticket.SetPresenters("Fabrikam");

                    return Task.CompletedTask;
                };

                options.Provider.OnValidateTokenRequest = context =>
                {
                    context.Skip();

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                Code = "SplxlOBeZQQYbYS6WxSbIA",
                GrantType = OpenIdConnectConstants.GrantTypes.AuthorizationCode,
                RedirectUri = null
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal("The mandatory 'redirect_uri' parameter is missing.", response.ErrorDescription);
        }

        [Fact]
        public async Task InvokeTokenEndpointAsync_AuthorizationCodeCausesAnErrorWhenRedirectUriIsInvalid()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnDeserializeAuthorizationCode = context =>
                {
                    Assert.Equal("SplxlOBeZQQYbYS6WxSbIA", context.AuthorizationCode);

                    context.Ticket = new AuthenticationTicket(
                        new ClaimsPrincipal(),
                        new AuthenticationProperties(),
                        OpenIdConnectServerDefaults.AuthenticationScheme);

                    context.Ticket.SetProperty(
                        OpenIdConnectConstants.Properties.OriginalRedirectUri,
                        "http://www.fabrikam.com/callback");

                    context.Ticket.SetPresenters("Fabrikam");

                    return Task.CompletedTask;
                };

                options.Provider.OnValidateTokenRequest = context =>
                {
                    context.Skip();

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                Code = "SplxlOBeZQQYbYS6WxSbIA",
                GrantType = OpenIdConnectConstants.GrantTypes.AuthorizationCode,
                RedirectUri = "http://www.contoso.com/redirect_uri"
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidGrant, response.Error);
            Assert.Equal("The specified 'redirect_uri' parameter doesn't match the client " +
                         "redirection endpoint the authorization code was initially sent to.", response.ErrorDescription);
        }

        [Fact]
        public async Task InvokeTokenEndpointAsync_AuthorizationCodeCausesAnErrorWhenCodeVerifierIsMissing()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnDeserializeAuthorizationCode = context =>
                {
                    Assert.Equal("SplxlOBeZQQYbYS6WxSbIA", context.AuthorizationCode);

                    context.Ticket = new AuthenticationTicket(
                        new ClaimsPrincipal(),
                        new AuthenticationProperties(),
                        OpenIdConnectServerDefaults.AuthenticationScheme);

                    context.Ticket.SetProperty(
                        OpenIdConnectConstants.Properties.CodeChallenge,
                        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");

                    context.Ticket.SetProperty(
                        OpenIdConnectConstants.Properties.CodeChallengeMethod,
                        OpenIdConnectConstants.CodeChallengeMethods.Sha256);

                    context.Ticket.SetPresenters("Fabrikam");

                    return Task.CompletedTask;
                };

                options.Provider.OnValidateTokenRequest = context =>
                {
                    context.Skip();

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                Code = "SplxlOBeZQQYbYS6WxSbIA",
                CodeVerifier = null,
                GrantType = OpenIdConnectConstants.GrantTypes.AuthorizationCode
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal("The mandatory 'code_verifier' parameter is missing.", response.ErrorDescription);
        }

        [Theory]
        [InlineData(OpenIdConnectConstants.CodeChallengeMethods.Plain, "challenge", "invalid_verifier")]
        [InlineData(OpenIdConnectConstants.CodeChallengeMethods.Sha256, "challenge", "invalid_verifier")]
        public async Task InvokeTokenEndpointAsync_AuthorizationCodeCausesAnErrorWhenCodeVerifierIsInvalid(string method, string challenge, string verifier)
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnDeserializeAuthorizationCode = context =>
                {
                    Assert.Equal("SplxlOBeZQQYbYS6WxSbIA", context.AuthorizationCode);

                    context.Ticket = new AuthenticationTicket(
                        new ClaimsPrincipal(),
                        new AuthenticationProperties(),
                        OpenIdConnectServerDefaults.AuthenticationScheme);

                    context.Ticket.SetProperty(OpenIdConnectConstants.Properties.CodeChallenge, challenge);
                    context.Ticket.SetProperty(OpenIdConnectConstants.Properties.CodeChallengeMethod, method);
                    context.Ticket.SetPresenters("Fabrikam");

                    return Task.CompletedTask;
                };

                options.Provider.OnValidateTokenRequest = context =>
                {
                    context.Skip();

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                Code = "SplxlOBeZQQYbYS6WxSbIA",
                CodeVerifier = verifier,
                GrantType = OpenIdConnectConstants.GrantTypes.AuthorizationCode
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidGrant, response.Error);
            Assert.Equal("The specified 'code_verifier' parameter is invalid.", response.ErrorDescription);
        }

        [Theory]
        [InlineData(OpenIdConnectConstants.CodeChallengeMethods.Plain,
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")]
        [InlineData(
            OpenIdConnectConstants.CodeChallengeMethods.Sha256,
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")]
        public async Task InvokeTokenEndpointAsync_TokenRequestSucceedsWhenCodeVerifierIsValid(string method, string challenge, string verifier)
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnDeserializeAuthorizationCode = context =>
                {
                    Assert.Equal("SplxlOBeZQQYbYS6WxSbIA", context.AuthorizationCode);
                    var identity = new ClaimsIdentity(OpenIdConnectServerDefaults.AuthenticationScheme);
                    identity.AddClaim(OpenIdConnectConstants.Claims.Subject, "Bob le Magnifique");

                    context.Ticket = new AuthenticationTicket(
                        new ClaimsPrincipal(identity),
                        new AuthenticationProperties(),
                        OpenIdConnectServerDefaults.AuthenticationScheme);

                    context.Ticket.SetProperty(OpenIdConnectConstants.Properties.CodeChallenge, challenge);
                    context.Ticket.SetProperty(OpenIdConnectConstants.Properties.CodeChallengeMethod, method);

                    context.Ticket.SetPresenters("Fabrikam");

                    return Task.CompletedTask;
                };

                options.Provider.OnValidateTokenRequest = context =>
                {
                    context.Skip();

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                Code = "SplxlOBeZQQYbYS6WxSbIA",
                CodeVerifier = verifier,
                GrantType = OpenIdConnectConstants.GrantTypes.AuthorizationCode
            });

            // Assert
            Assert.NotNull(response.AccessToken);
        }

        [Fact]
        public async Task InvokeTokenEndpointAsync_RefreshTokenCausesAnErrorWhenScopeIsUnexpected()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnDeserializeRefreshToken = context =>
                {
                    Assert.Equal("8xLOxBtZp8", context.RefreshToken);

                    context.Ticket = new AuthenticationTicket(
                        new ClaimsPrincipal(),
                        new AuthenticationProperties(),
                        OpenIdConnectServerDefaults.AuthenticationScheme);

                    context.Ticket.SetScopes(Enumerable.Empty<string>());

                    return Task.CompletedTask;
                };

                options.Provider.OnValidateTokenRequest = context =>
                {
                    context.Skip();

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                GrantType = OpenIdConnectConstants.GrantTypes.RefreshToken,
                RefreshToken = "8xLOxBtZp8",
                Scope = "profile phone"
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidGrant, response.Error);
            Assert.Equal("The 'scope' parameter is not valid in this context.", response.ErrorDescription);
        }

        [Fact]
        public async Task InvokeTokenEndpointAsync_RefreshTokenCausesAnErrorWhenScopeIsInvalid()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnDeserializeRefreshToken = context =>
                {
                    Assert.Equal("8xLOxBtZp8", context.RefreshToken);

                    context.Ticket = new AuthenticationTicket(
                        new ClaimsPrincipal(),
                        new AuthenticationProperties(),
                        OpenIdConnectServerDefaults.AuthenticationScheme);

                    context.Ticket.SetScopes("profile", "email");

                    return Task.CompletedTask;
                };

                options.Provider.OnValidateTokenRequest = context =>
                {
                    context.Skip();

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                GrantType = OpenIdConnectConstants.GrantTypes.RefreshToken,
                RefreshToken = "8xLOxBtZp8",
                Scope = "profile phone"
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidGrant, response.Error);
            Assert.Equal("The specified 'scope' parameter is invalid.", response.ErrorDescription);
        }

        [Theory]
        [InlineData("custom_error", null, null)]
        [InlineData("custom_error", "custom_description", null)]
        [InlineData("custom_error", "custom_description", "custom_uri")]
        [InlineData(null, "custom_description", null)]
        [InlineData(null, "custom_description", "custom_uri")]
        [InlineData(null, null, "custom_uri")]
        [InlineData(null, null, null)]
        public async Task InvokeTokenEndpointAsync_HandleTokenRequest_AllowsRejectingRequest(string error, string description, string uri)
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnValidateTokenRequest = context =>
                {
                    context.Skip();

                    return Task.CompletedTask;
                };

                options.Provider.OnHandleTokenRequest = context =>
                {
                    context.Reject(error, description, uri);

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                GrantType = OpenIdConnectConstants.GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w"
            });

            // Assert
            Assert.Equal(error ?? OpenIdConnectConstants.Errors.InvalidGrant, response.Error);
            Assert.Equal(description, response.ErrorDescription);
            Assert.Equal(uri, response.ErrorUri);
        }

        [Fact]
        public async Task InvokeTokenEndpointAsync_HandleTokenRequest_AllowsHandlingResponse()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnValidateTokenRequest = context =>
                {
                    context.Skip();

                    return Task.CompletedTask;
                };

                options.Provider.OnHandleTokenRequest = context =>
                {
                    context.HandleResponse();

                    context.HttpContext.Response.Headers[HeaderNames.ContentType] = "application/json";

                    return context.HttpContext.Response.WriteAsync(JsonConvert.SerializeObject(new
                    {
                        name = "Bob le Magnifique"
                    }));
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                GrantType = OpenIdConnectConstants.GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w"
            });

            // Assert
            Assert.Equal("Bob le Magnifique", (string) response["name"]);
        }

        [Fact]
        public async Task InvokeTokenEndpointAsync_HandleTokenRequest_AllowsSkippingHandler()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnValidateTokenRequest = context =>
                {
                    context.Skip();

                    return Task.CompletedTask;
                };

                options.Provider.OnHandleTokenRequest = context =>
                {
                    context.SkipHandler();

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                GrantType = OpenIdConnectConstants.GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w"
            });

            // Assert
            Assert.Equal("Bob le Magnifique", (string) response["name"]);
        }

        [Fact]
        public async Task InvokeTokenEndpointAsync_RejectsUnhandledRequestsWithDefaultError()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnValidateTokenRequest = context =>
                {
                    context.Skip();

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                GrantType = OpenIdConnectConstants.GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w"
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal("The token request was rejected by the authorization server.", response.ErrorDescription);
        }

        [Fact]
        public async Task SendTokenResponseAsync_ApplyTokenResponse_AllowsHandlingResponse()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnValidateTokenRequest = context =>
                {
                    context.Skip();

                    return Task.CompletedTask;
                };

                options.Provider.OnHandleTokenRequest = context =>
                {
                    var identity = new ClaimsIdentity(OpenIdConnectServerDefaults.AuthenticationScheme);
                    identity.AddClaim(OpenIdConnectConstants.Claims.Subject, "Bob le Magnifique");

                    context.Validate(new ClaimsPrincipal(identity));

                    return Task.CompletedTask;
                };

                options.Provider.OnApplyTokenResponse = context =>
                {
                    context.HandleResponse();

                    context.HttpContext.Response.Headers[HeaderNames.ContentType] = "application/json";

                    return context.HttpContext.Response.WriteAsync(JsonConvert.SerializeObject(new
                    {
                        name = "Bob le Magnifique"
                    }));
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                GrantType = OpenIdConnectConstants.GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w"
            });

            // Assert
            Assert.Equal("Bob le Magnifique", (string) response["name"]);
        }

        [Fact]
        public async Task SendTokenResponseAsync_ApplyTokenResponse_ResponseContainsCustomParameters()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnValidateTokenRequest = context =>
                {
                    context.Skip();

                    return Task.CompletedTask;
                };

                options.Provider.OnHandleTokenRequest = context =>
                {
                    var identity = new ClaimsIdentity(OpenIdConnectServerDefaults.AuthenticationScheme);
                    identity.AddClaim(OpenIdConnectConstants.Claims.Subject, "Bob le Magnifique");

                    context.Validate(new ClaimsPrincipal(identity));

                    return Task.CompletedTask;
                };

                options.Provider.OnApplyTokenResponse = context =>
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

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                GrantType = OpenIdConnectConstants.GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w"
            });

            // Assert
            Assert.Equal("custom_value", (string) response["custom_parameter"]);
            Assert.Equal(new[] { "custom_value_1", "custom_value_2" }, (string[]) response["parameter_with_multiple_values"]);
        }
    }
}
