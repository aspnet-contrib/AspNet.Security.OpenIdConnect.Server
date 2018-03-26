/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Client;
using AspNet.Security.OpenIdConnect.Primitives;
using Newtonsoft.Json;
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
        public async Task InvokeLogoutEndpointAsync_UnexpectedMethodReturnsAnError(string method)
        {
            // Arrange
            var server = CreateAuthorizationServer();

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.SendAsync(method, LogoutEndpoint, new OpenIdConnectRequest());

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
        public async Task InvokeLogoutEndpointAsync_ExtractLogoutRequest_AllowsRejectingRequest(string error, string description, string uri)
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnExtractLogoutRequest = context =>
                {
                    context.Reject(error, description, uri);

                    return Task.CompletedTask;
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
        public async Task InvokeLogoutEndpointAsync_ExtractLogoutRequest_AllowsHandlingResponse()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnExtractLogoutRequest = context =>
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
            var response = await client.GetAsync(LogoutEndpoint);

            // Assert
            Assert.Equal("Bob le Bricoleur", (string) response["name"]);
        }

        [Fact]
        public async Task InvokeLogoutEndpointAsync_ExtractLogoutRequest_AllowsSkippingToNextMiddleware()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnExtractLogoutRequest = context =>
                {
                    context.SkipToNextMiddleware();

                    return Task.CompletedTask;
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
        public async Task InvokeLogoutEndpointAsync_ValidateLogoutRequest_AllowsRejectingRequest(string error, string description, string uri)
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnValidateLogoutRequest = context =>
                {
                    context.Reject(error, description, uri);

                    return Task.CompletedTask;
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
        public async Task InvokeLogoutEndpointAsync_ValidateLogoutRequest_AllowsHandlingResponse()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnValidateLogoutRequest = context =>
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
            var response = await client.PostAsync(LogoutEndpoint, new OpenIdConnectRequest());

            // Assert
            Assert.Equal("Bob le Magnifique", (string) response["name"]);
        }

        [Fact]
        public async Task InvokeLogoutEndpointAsync_ValidateLogoutRequest_AllowsSkippingToNextMiddleware()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnValidateLogoutRequest = context =>
                {
                    context.SkipToNextMiddleware();

                    return Task.CompletedTask;
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
        public async Task InvokeLogoutEndpointAsync_HandleLogoutRequest_AllowsRejectingRequest(string error, string description, string uri)
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnValidateLogoutRequest = context =>
                {
                    context.Validate();

                    return Task.CompletedTask;
                };

                options.Provider.OnHandleLogoutRequest = context =>
                {
                    context.Reject(error, description, uri);

                    return Task.CompletedTask;
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
        public async Task InvokeLogoutEndpointAsync_HandleLogoutRequest_AllowsHandlingResponse()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnValidateLogoutRequest = context =>
                {
                    context.Validate();

                    return Task.CompletedTask;
                };

                options.Provider.OnHandleLogoutRequest = context =>
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
            var response = await client.PostAsync(LogoutEndpoint, new OpenIdConnectRequest());

            // Assert
            Assert.Equal("Bob le Magnifique", (string) response["name"]);
        }

        [Fact]
        public async Task InvokeLogoutEndpointAsync_HandleLogoutRequest_AllowsSkippingToNextMiddleware()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnValidateLogoutRequest = context =>
                {
                    context.Validate();

                    return Task.CompletedTask;
                };

                options.Provider.OnHandleLogoutRequest = context =>
                {
                    context.SkipToNextMiddleware();

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(LogoutEndpoint, new OpenIdConnectRequest());

            // Assert
            Assert.Equal("Bob le Magnifique", (string) response["name"]);
        }

        [Fact]
        public async Task SendLogoutResponseAsync_ApplyLogoutResponse_AllowsHandlingResponse()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnValidateLogoutRequest = context =>
                {
                    context.Validate();

                    return Task.CompletedTask;
                };

                options.Provider.OnHandleLogoutRequest = context =>
                {
                    context.OwinContext.Authentication.SignOut(context.Options.AuthenticationType);
                    context.HandleResponse();

                    return Task.CompletedTask;
                };

                options.Provider.OnApplyLogoutResponse = context =>
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
            var response = await client.PostAsync(LogoutEndpoint, new OpenIdConnectRequest());

            // Assert
            Assert.Equal("Bob le Magnifique", (string) response["name"]);
        }

        [Fact]
        public async Task SendLogoutResponseAsync_ApplyLogoutResponse_ResponseContainsCustomParameters()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnValidateLogoutRequest = context =>
                {
                    context.Validate();

                    return Task.CompletedTask;
                };

                options.Provider.OnHandleLogoutRequest = context =>
                {
                    context.OwinContext.Authentication.SignOut(context.Options.AuthenticationType);
                    context.HandleResponse();

                    return Task.CompletedTask;
                };

                options.Provider.OnApplyLogoutResponse = context =>
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
            var response = await client.PostAsync(LogoutEndpoint, new OpenIdConnectRequest
            {
                PostLogoutRedirectUri = "http://www.fabrikam.com/path"
            });

            // Assert
            Assert.Equal("custom_value", (string) response["custom_parameter"]);
            Assert.Equal(new[] { "custom_value_1", "custom_value_2" }, (string[]) response["parameter_with_multiple_values"]);
        }

        [Fact]
        public async Task SendLogoutResponseAsync_ThrowsAnExceptionWhenRequestIsMissing()
        {
            // Note: an exception is only thrown if the request was not properly extracted
            // AND if the developer decided to override the error to return a custom response.
            // To emulate this behavior, the error property is manually set to null.

            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnApplyLogoutResponse = context =>
                {
                    context.Response.Error = null;
                    context.PostLogoutRedirectUri = "http://www.fabrikam.com/path";

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act and assert
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
            {
                return client.SendAsync(Put, LogoutEndpoint, new OpenIdConnectRequest());
            });

            Assert.Equal("The logout response cannot be returned.", exception.Message);
        }

        [Fact]
        public async Task SendLogoutResponseAsync_DoesNotSetStateWhenUserIsNotRedirected()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnHandleLogoutRequest = context =>
                {
                    context.OwinContext.Authentication.SignOut(context.Options.AuthenticationType);
                    context.HandleResponse();

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(LogoutEndpoint, new OpenIdConnectRequest
            {
                State = "af0ifjsldkj"
            });

            // Assert
            Assert.Null(response.State);
        }

        [Fact]
        public async Task SendLogoutResponseAsync_FlowsStateWhenRedirectUriIsUsed()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnValidateLogoutRequest = context =>
                {
                    context.Validate();

                    return Task.CompletedTask;
                };

                options.Provider.OnHandleLogoutRequest = context =>
                {
                    context.OwinContext.Authentication.SignOut(context.Options.AuthenticationType);
                    context.HandleResponse();

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(LogoutEndpoint, new OpenIdConnectRequest
            {
                PostLogoutRedirectUri = "http://www.fabrikam.com/path",
                State = "af0ifjsldkj"
            });

            // Assert
            Assert.Equal("af0ifjsldkj", response.State);
        }

        [Fact]
        public async Task SendLogoutResponseAsync_DoesNotOverrideStateSetByApplicationCode()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnValidateLogoutRequest = context =>
                {
                    context.Validate();

                    return Task.CompletedTask;
                };

                options.Provider.OnHandleLogoutRequest = context =>
                {
                    context.OwinContext.Authentication.SignOut(context.Options.AuthenticationType);
                    context.HandleResponse();

                    return Task.CompletedTask;
                };

                options.Provider.OnApplyLogoutResponse = context =>
                {
                    context.Response.State = "custom_state";

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(LogoutEndpoint, new OpenIdConnectRequest
            {
                PostLogoutRedirectUri = "http://www.fabrikam.com/path",
                State = "af0ifjsldkj"
            });

            // Assert
            Assert.Equal("custom_state", response.State);
        }
    }
}
