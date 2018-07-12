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
        [InlineData(nameof(Head))]
        [InlineData(nameof(Options))]
        [InlineData(nameof(Put))]
        [InlineData(nameof(Trace))]
        public async Task InvokeUserinfoEndpointAsync_UnexpectedMethodReturnsAnError(string method)
        {
            // Arrange
            var server = CreateAuthorizationServer();

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.SendAsync(method, UserinfoEndpoint, new OpenIdConnectRequest());

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
        public async Task InvokeUserinfoEndpointAsync_ExtractUserinfoRequest_AllowsRejectingRequest(string error, string description, string uri)
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnExtractUserinfoRequest = context =>
                {
                    context.Reject(error, description, uri);

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(UserinfoEndpoint, new OpenIdConnectRequest());

            // Assert
            Assert.Equal(error ?? OpenIdConnectConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal(description, response.ErrorDescription);
            Assert.Equal(uri, response.ErrorUri);
        }

        [Fact]
        public async Task InvokeUserinfoEndpointAsync_ExtractUserinfoRequest_AllowsHandlingResponse()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnExtractUserinfoRequest = context =>
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
            var response = await client.GetAsync(UserinfoEndpoint);

            // Assert
            Assert.Equal("Bob le Bricoleur", (string) response["name"]);
        }

        [Fact]
        public async Task InvokeUserinfoEndpointAsync_ExtractUserinfoRequest_AllowsSkippingToNextMiddleware()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnExtractUserinfoRequest = context =>
                {
                    context.SkipToNextMiddleware();

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.GetAsync(UserinfoEndpoint);

            // Assert
            Assert.Equal("Bob le Magnifique", (string) response["name"]);
        }

        [Fact]
        public async Task InvokeUserinfoEndpointAsync_MissingTokenCausesAnError()
        {
            // Arrange
            var server = CreateAuthorizationServer();

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(UserinfoEndpoint, new OpenIdConnectRequest
            {
                AccessToken = null
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal("The mandatory 'access_token' parameter is missing.", response.ErrorDescription);
        }

        [Theory]
        [InlineData("custom_error", null, null)]
        [InlineData("custom_error", "custom_description", null)]
        [InlineData("custom_error", "custom_description", "custom_uri")]
        [InlineData(null, "custom_description", null)]
        [InlineData(null, "custom_description", "custom_uri")]
        [InlineData(null, null, "custom_uri")]
        [InlineData(null, null, null)]
        public async Task InvokeUserinfoEndpointAsync_ValidateUserinfoRequest_AllowsRejectingRequest(string error, string description, string uri)
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnValidateUserinfoRequest = context =>
                {
                    context.Reject(error, description, uri);

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(UserinfoEndpoint, new OpenIdConnectRequest
            {
                AccessToken = "SlAV32hkKG"
            });

            // Assert
            Assert.Equal(error ?? OpenIdConnectConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal(description, response.ErrorDescription);
            Assert.Equal(uri, response.ErrorUri);
        }

        [Fact]
        public async Task InvokeUserinfoEndpointAsync_ValidateUserinfoRequest_AllowsHandlingResponse()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnValidateUserinfoRequest = context =>
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
            var response = await client.PostAsync(UserinfoEndpoint, new OpenIdConnectRequest
            {
                AccessToken = "SlAV32hkKG"
            });

            // Assert
            Assert.Equal("Bob le Magnifique", (string) response["name"]);
        }

        [Fact]
        public async Task InvokeUserinfoEndpointAsync_ValidateUserinfoRequest_AllowsSkippingToNextMiddleware()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnValidateUserinfoRequest = context =>
                {
                    context.SkipToNextMiddleware();

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(UserinfoEndpoint, new OpenIdConnectRequest
            {
                AccessToken = "SlAV32hkKG"
            });

            // Assert
            Assert.Equal("Bob le Magnifique", (string) response["name"]);
        }

        [Fact]
        public async Task InvokeUserinfoEndpointAsync_InvalidTokenCausesAnError()
        {
            // Arrange
            var server = CreateAuthorizationServer();

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(UserinfoEndpoint, new OpenIdConnectRequest
            {
                AccessToken = "SlAV32hkKG"
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidToken, response.Error);
            Assert.Equal("The specified access token is not valid.", response.ErrorDescription);
        }

        [Fact]
        public async Task InvokeUserinfoEndpointAsync_ExpiredTokenCausesAnError()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnDeserializeAccessToken = context =>
                {
                    Assert.Equal("SlAV32hkKG", context.AccessToken);

                    context.Ticket = new AuthenticationTicket(
                        new ClaimsIdentity(context.Options.AuthenticationType),
                        new AuthenticationProperties());

                    context.Ticket.Properties.ExpiresUtc = options.SystemClock.UtcNow - TimeSpan.FromDays(1);

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(UserinfoEndpoint, new OpenIdConnectRequest
            {
                AccessToken = "SlAV32hkKG"
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidToken, response.Error);
            Assert.Equal("The specified access token is no longer valid.", response.ErrorDescription);
        }

        [Fact]
        public async Task InvokeUserinfoEndpointAsync_MissingSubjectClaimCausesAnException()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnDeserializeAccessToken = context =>
                {
                    Assert.Equal("SlAV32hkKG", context.AccessToken);

                    context.Ticket = new AuthenticationTicket(
                        new ClaimsIdentity(context.Options.AuthenticationType),
                        new AuthenticationProperties());

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act and assert
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
            {
                return client.PostAsync(UserinfoEndpoint, new OpenIdConnectRequest
                {
                    AccessToken = "SlAV32hkKG"
                });
            });

            Assert.Equal("The subject claim cannot be null or empty.", exception.Message);
        }

        [Fact]
        public async Task InvokeUserinfoEndpointAsync_BasicClaimsAreCorrectlyReturned()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnDeserializeAccessToken = context =>
                {
                    Assert.Equal("SlAV32hkKG", context.AccessToken);

                    var identity = new ClaimsIdentity(context.Options.AuthenticationType);
                    identity.AddClaim(OpenIdConnectConstants.Claims.Subject, "Bob le Magnifique");

                    context.Ticket = new AuthenticationTicket(identity, new AuthenticationProperties());
                    context.Ticket.SetPresenters("Fabrikam", "Contoso");

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(UserinfoEndpoint, new OpenIdConnectRequest
            {
                AccessToken = "SlAV32hkKG"
            });

            // Assert
            Assert.Equal(3, response.GetParameters().Count());
            Assert.Equal(server.BaseAddress.AbsoluteUri, (string) response[OpenIdConnectConstants.Claims.Issuer]);
            Assert.Equal("Bob le Magnifique", (string) response[OpenIdConnectConstants.Claims.Subject]);
            Assert.Equal(new[] { "Fabrikam", "Contoso" }, (string[]) response[OpenIdConnectConstants.Claims.Audience]);
        }

        [Fact]
        public async Task InvokeUserinfoEndpointAsync_NonBasicClaimsAreNotReturnedWhenNoScopeWasGranted()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnDeserializeAccessToken = context =>
                {
                    Assert.Equal("SlAV32hkKG", context.AccessToken);

                    var identity = new ClaimsIdentity(context.Options.AuthenticationType);
                    identity.AddClaim(OpenIdConnectConstants.Claims.Subject, "Bob le Magnifique");
                    identity.AddClaim(OpenIdConnectConstants.Claims.GivenName, "Bob");
                    identity.AddClaim(OpenIdConnectConstants.Claims.FamilyName, "Saint-Clar");
                    identity.AddClaim(OpenIdConnectConstants.Claims.Birthdate, "04/09/1933");
                    identity.AddClaim(OpenIdConnectConstants.Claims.Email, "bob@le-magnifique.com");
                    identity.AddClaim(OpenIdConnectConstants.Claims.PhoneNumber, "0148962355");

                    context.Ticket = new AuthenticationTicket(identity, new AuthenticationProperties());
                    context.Ticket.SetPresenters("Fabrikam");

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(UserinfoEndpoint, new OpenIdConnectRequest
            {
                AccessToken = "SlAV32hkKG"
            });

            // Assert
            Assert.Equal(3, response.GetParameters().Count());
            Assert.Equal(server.BaseAddress.AbsoluteUri, (string) response[OpenIdConnectConstants.Claims.Issuer]);
            Assert.Equal("Bob le Magnifique", (string) response[OpenIdConnectConstants.Claims.Subject]);
            Assert.Equal("Fabrikam", (string) response[OpenIdConnectConstants.Claims.Audience]);
        }

        [Fact]
        public async Task InvokeUserinfoEndpointAsync_ProfileClaimsAreCorrectlyReturned()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnDeserializeAccessToken = context =>
                {
                    Assert.Equal("SlAV32hkKG", context.AccessToken);

                    var identity = new ClaimsIdentity(context.Options.AuthenticationType);
                    identity.AddClaim(OpenIdConnectConstants.Claims.Subject, "Bob le Magnifique");
                    identity.AddClaim(OpenIdConnectConstants.Claims.GivenName, "Bob");
                    identity.AddClaim(OpenIdConnectConstants.Claims.FamilyName, "Saint-Clar");
                    identity.AddClaim(OpenIdConnectConstants.Claims.Birthdate, "04/09/1933");

                    context.Ticket = new AuthenticationTicket(identity, new AuthenticationProperties());
                    context.Ticket.SetPresenters("Fabrikam");
                    context.Ticket.SetScopes(OpenIdConnectConstants.Scopes.Profile);

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(UserinfoEndpoint, new OpenIdConnectRequest
            {
                AccessToken = "SlAV32hkKG"
            });

            // Assert
            Assert.Equal("Bob", (string) response[OpenIdConnectConstants.Claims.GivenName]);
            Assert.Equal("Saint-Clar", (string) response[OpenIdConnectConstants.Claims.FamilyName]);
            Assert.Equal("04/09/1933", (string) response[OpenIdConnectConstants.Claims.Birthdate]);
        }

        [Fact]
        public async Task InvokeUserinfoEndpointAsync_EmailClaimIsCorrectlyReturned()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnDeserializeAccessToken = context =>
                {
                    Assert.Equal("SlAV32hkKG", context.AccessToken);

                    var identity = new ClaimsIdentity(context.Options.AuthenticationType);
                    identity.AddClaim(OpenIdConnectConstants.Claims.Subject, "Bob le Magnifique");
                    identity.AddClaim(OpenIdConnectConstants.Claims.Email, "bob@le-magnifique.com");

                    context.Ticket = new AuthenticationTicket(identity, new AuthenticationProperties());
                    context.Ticket.SetPresenters("Fabrikam");
                    context.Ticket.SetScopes(OpenIdConnectConstants.Scopes.Email);

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(UserinfoEndpoint, new OpenIdConnectRequest
            {
                AccessToken = "SlAV32hkKG"
            });

            // Assert
            Assert.Equal("bob@le-magnifique.com", (string) response[OpenIdConnectConstants.Claims.Email]);
        }

        [Fact]
        public async Task InvokeUserinfoEndpointAsync_PhoneClaimIsCorrectlyReturned()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnDeserializeAccessToken = context =>
                {
                    Assert.Equal("SlAV32hkKG", context.AccessToken);

                    var identity = new ClaimsIdentity(context.Options.AuthenticationType);
                    identity.AddClaim(OpenIdConnectConstants.Claims.Subject, "Bob le Magnifique");
                    identity.AddClaim(OpenIdConnectConstants.Claims.PhoneNumber, "0148962355");

                    context.Ticket = new AuthenticationTicket(identity, new AuthenticationProperties());
                    context.Ticket.SetPresenters("Fabrikam");
                    context.Ticket.SetScopes(OpenIdConnectConstants.Scopes.Phone);

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(UserinfoEndpoint, new OpenIdConnectRequest
            {
                AccessToken = "SlAV32hkKG"
            });

            // Assert
            Assert.Equal("0148962355", (string) response[OpenIdConnectConstants.Claims.PhoneNumber]);
        }

        [Theory]
        [InlineData("custom_error", null, null)]
        [InlineData("custom_error", "custom_description", null)]
        [InlineData("custom_error", "custom_description", "custom_uri")]
        [InlineData(null, "custom_description", null)]
        [InlineData(null, "custom_description", "custom_uri")]
        [InlineData(null, null, "custom_uri")]
        [InlineData(null, null, null)]
        public async Task InvokeUserinfoEndpointAsync_HandleUserinfoRequest_AllowsRejectingRequest(string error, string description, string uri)
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnDeserializeAccessToken = context =>
                {
                    Assert.Equal("SlAV32hkKG", context.AccessToken);

                    context.Ticket = new AuthenticationTicket(
                        new ClaimsIdentity(context.Options.AuthenticationType),
                        new AuthenticationProperties());

                    return Task.CompletedTask;
                };

                options.Provider.OnHandleUserinfoRequest = context =>
                {
                    context.Reject(error, description, uri);

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(UserinfoEndpoint, new OpenIdConnectRequest
            {
                AccessToken = "SlAV32hkKG"
            });

            // Assert
            Assert.Equal(error ?? OpenIdConnectConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal(description, response.ErrorDescription);
            Assert.Equal(uri, response.ErrorUri);
        }

        [Fact]
        public async Task InvokeUserinfoEndpointAsync_HandleUserinfoRequest_AllowsHandlingResponse()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnDeserializeAccessToken = context =>
                {
                    Assert.Equal("SlAV32hkKG", context.AccessToken);

                    context.Ticket = new AuthenticationTicket(
                        new ClaimsIdentity(context.Options.AuthenticationType),
                        new AuthenticationProperties());

                    return Task.CompletedTask;
                };

                options.Provider.OnHandleUserinfoRequest = context =>
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
            var response = await client.PostAsync(UserinfoEndpoint, new OpenIdConnectRequest
            {
                AccessToken = "SlAV32hkKG"
            });

            // Assert
            Assert.Equal("Bob le Magnifique", (string) response["name"]);
        }

        [Fact]
        public async Task InvokeUserinfoEndpointAsync_HandleUserinfoRequest_AllowsSkippingToNextMiddleware()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnDeserializeAccessToken = context =>
                {
                    Assert.Equal("SlAV32hkKG", context.AccessToken);

                    context.Ticket = new AuthenticationTicket(
                        new ClaimsIdentity(context.Options.AuthenticationType),
                        new AuthenticationProperties());

                    return Task.CompletedTask;
                };

                options.Provider.OnHandleUserinfoRequest = context =>
                {
                    context.SkipToNextMiddleware();

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(UserinfoEndpoint, new OpenIdConnectRequest
            {
                AccessToken = "SlAV32hkKG"
            });

            // Assert
            Assert.Equal("Bob le Magnifique", (string) response["name"]);
        }

        [Fact]
        public async Task SendUserinfoResponseAsync_ApplyUserinfoResponse_AllowsHandlingResponse()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnDeserializeAccessToken = context =>
                {
                    Assert.Equal("SlAV32hkKG", context.AccessToken);

                    context.Ticket = new AuthenticationTicket(
                        new ClaimsIdentity(context.Options.AuthenticationType),
                        new AuthenticationProperties());

                    return Task.CompletedTask;
                };

                options.Provider.OnApplyUserinfoResponse = context =>
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
            var response = await client.PostAsync(UserinfoEndpoint, new OpenIdConnectRequest
            {
                Token = "SlAV32hkKG"
            });

            // Assert
            Assert.Equal("Bob le Magnifique", (string) response["name"]);
        }

        [Fact]
        public async Task SendUserinfoResponseAsync_ApplyUserinfoResponse_ResponseContainsCustomParameters()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnDeserializeAccessToken = context =>
                {
                    Assert.Equal("SlAV32hkKG", context.AccessToken);

                    context.Ticket = new AuthenticationTicket(
                        new ClaimsIdentity(context.Options.AuthenticationType),
                        new AuthenticationProperties());

                    return Task.CompletedTask;
                };

                options.Provider.OnApplyUserinfoResponse = context =>
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
            var response = await client.PostAsync(UserinfoEndpoint, new OpenIdConnectRequest
            {
                Token = "SlAV32hkKG"
            });

            // Assert
            Assert.Equal("custom_value", (string) response["custom_parameter"]);
            Assert.Equal(new[] { "custom_value_1", "custom_value_2" }, (string[]) response["parameter_with_multiple_values"]);
        }
    }
}
