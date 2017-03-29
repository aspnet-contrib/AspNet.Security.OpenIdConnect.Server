/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.Security.Claims;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Client;
using AspNet.Security.OpenIdConnect.Extensions;
using AspNet.Security.OpenIdConnect.Primitives;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Authentication;
using Microsoft.IdentityModel.Tokens;
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
        [InlineData(nameof(Head))]
        [InlineData(nameof(Options))]
        [InlineData(nameof(Put))]
        [InlineData(nameof(Trace))]
        public async Task InvokeAuthorizationEndpointAsync_UnexpectedMethodReturnsAnError(string method)
        {
            // Arrange
            var server = CreateAuthorizationServer();

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.SendAsync(method, AuthorizationEndpoint, new OpenIdConnectRequest());

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal("A malformed authorization request has been received: " +
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
        public async Task InvokeAuthorizationEndpointAsync_ExtractAuthorizationRequest_AllowsRejectingRequest(string error, string description, string uri)
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnExtractAuthorizationRequest = context =>
                {
                    context.Reject(error, description, uri);

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.GetAsync(AuthorizationEndpoint);

            // Assert
            Assert.Equal(error ?? OpenIdConnectConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal(description, response.ErrorDescription);
            Assert.Equal(uri, response.ErrorUri);
        }

        [Fact]
        public async Task InvokeAuthorizationEndpointAsync_ExtractAuthorizationRequest_AllowsHandlingResponse()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnExtractAuthorizationRequest = context =>
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
            var response = await client.GetAsync(AuthorizationEndpoint);

            // Assert
            Assert.Equal("Bob le Magnifique", (string) response["name"]);
        }

        [Fact]
        public async Task InvokeAuthorizationEndpointAsync_ExtractAuthorizationRequest_AllowsSkippingToNextMiddleware()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnExtractAuthorizationRequest = context =>
                {
                    context.SkipToNextMiddleware();

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.GetAsync(AuthorizationEndpoint);

            // Assert
            Assert.Equal("Bob le Magnifique", (string) response["name"]);
        }

        [Fact]
        public async Task InvokeAuthorizationEndpointAsync_MissingClientIdCausesAnError()
        {
            // Arrange
            var server = CreateAuthorizationServer();

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(AuthorizationEndpoint, new OpenIdConnectRequest
            {
                ClientId = null
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal("client_id was missing", response.ErrorDescription);
        }

        [Fact]
        public async Task InvokeAuthorizationEndpointAsync_MissingRedirectUriCausesAnErrorForOpenIdRequests()
        {
            // Arrange
            var server = CreateAuthorizationServer();

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(AuthorizationEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                RedirectUri = null,
                Scope = OpenIdConnectConstants.Scopes.OpenId
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal("redirect_uri must be included when making an OpenID Connect request", response.ErrorDescription);
        }

        [Theory]
        [InlineData("/path", "redirect_uri must be absolute")]
        [InlineData("http://www.fabrikam.com/path#param=value", "redirect_uri must not include a fragment")]
        public async Task InvokeAuthorizationEndpointAsync_InvalidRedirectUriCausesAnError(string address, string message)
        {
            // Arrange
            var server = CreateAuthorizationServer();

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(AuthorizationEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                RedirectUri = address,
                Scope = OpenIdConnectConstants.Scopes.OpenId
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal(message, response.ErrorDescription);
        }

        [Fact]
        public async Task InvokeAuthorizationEndpointAsync_MissingResponseTypeCausesAnError()
        {
            // Arrange
            var server = CreateAuthorizationServer();

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(AuthorizationEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = null,
                Scope = OpenIdConnectConstants.Scopes.OpenId
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal("response_type parameter missing", response.ErrorDescription);
        }

        [Theory]
        [InlineData("code id_token", OpenIdConnectConstants.ResponseModes.Query)]
        [InlineData("code id_token token", OpenIdConnectConstants.ResponseModes.Query)]
        [InlineData("code token", OpenIdConnectConstants.ResponseModes.Query)]
        [InlineData("id_token", OpenIdConnectConstants.ResponseModes.Query)]
        [InlineData("id_token token", OpenIdConnectConstants.ResponseModes.Query)]
        [InlineData("token", OpenIdConnectConstants.ResponseModes.Query)]
        public async Task InvokeAuthorizationEndpointAsync_UnsafeResponseModeCausesAnError(string type, string mode)
        {
            // Arrange
            var server = CreateAuthorizationServer();

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(AuthorizationEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseMode = mode,
                ResponseType = type,
                Scope = OpenIdConnectConstants.Scopes.OpenId
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal("response_type/response_mode combination unsupported", response.ErrorDescription);
        }

        [Theory]
        [InlineData("code id_token")]
        [InlineData("code id_token token")]
        [InlineData("code token")]
        [InlineData("id_token")]
        [InlineData("id_token token")]
        [InlineData("token")]
        public async Task InvokeAuthorizationEndpointAsync_MissingNonceCausesAnErrorForOpenIdRequests(string type)
        {
            // Arrange
            var server = CreateAuthorizationServer();

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(AuthorizationEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = type,
                Scope = OpenIdConnectConstants.Scopes.OpenId
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal("nonce parameter missing", response.ErrorDescription);
        }

        [Theory]
        [InlineData("code id_token")]
        [InlineData("code id_token token")]
        [InlineData("id_token")]
        [InlineData("id_token token")]
        public async Task InvokeAuthorizationEndpointAsync_MissingOpenIdScopeCausesAnErrorForOpenIdRequests(string type)
        {
            // Arrange
            var server = CreateAuthorizationServer();

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(AuthorizationEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = type
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal("openid scope missing", response.ErrorDescription);
        }

        [Theory]
        [InlineData("code id_token")]
        [InlineData("code id_token token")]
        [InlineData("id_token")]
        [InlineData("id_token token")]
        public async Task InvokeAuthorizationEndpointAsync_IdTokenResponseTypeCausesAnErrorWhenNoAsymmetricSigningKeyIsRegistered(string type)
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.SigningCredentials.Clear();
                options.SigningCredentials.AddKey(new SymmetricSecurityKey(new byte[256 / 8]));
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(AuthorizationEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                Nonce = "n-0S6_WzA2Mj",
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = type,
                Scope = OpenIdConnectConstants.Scopes.OpenId
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.UnsupportedResponseType, response.Error);
            Assert.Equal("The specified response type is not supported by this server.", response.ErrorDescription);
        }

        [Theory]
        [InlineData("none consent")]
        [InlineData("none login")]
        [InlineData("none select_account")]
        public async Task InvokeAuthorizationEndpointAsync_InvalidPromptCausesAnError(string prompt)
        {
            // Arrange
            var server = CreateAuthorizationServer();

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(AuthorizationEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                Nonce = "n-0S6_WzA2Mj",
                Prompt = prompt,
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = "code id_token token",
                Scope = OpenIdConnectConstants.Scopes.OpenId
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal("The specified 'prompt' parameter is invalid.", response.ErrorDescription);
        }

        [Theory]
        [InlineData("none")]
        [InlineData("consent")]
        [InlineData("login")]
        [InlineData("select_account")]
        [InlineData("consent login")]
        [InlineData("consent select_account")]
        [InlineData("login select_account")]
        [InlineData("consent login select_account")]
        public async Task InvokeAuthorizationEndpointAsync_ValidPromptDoesNotCauseAnError(string prompt)
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnValidateAuthorizationRequest = context =>
                {
                    context.Validate();

                    return Task.FromResult(0);
                };

                options.Provider.OnHandleAuthorizationRequest = context =>
                {
                    var identity = new ClaimsIdentity(context.Options.AuthenticationScheme);
                    identity.AddClaim(OpenIdConnectConstants.Claims.Subject, "Bob le Magnifique");

                    var ticket = new AuthenticationTicket(
                        new ClaimsPrincipal(identity),
                        new AuthenticationProperties(),
                        context.Options.AuthenticationScheme);

                    context.Validate(ticket);

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(AuthorizationEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                Nonce = "n-0S6_WzA2Mj",
                Prompt = prompt,
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = "code id_token token",
                Scope = OpenIdConnectConstants.Scopes.OpenId
            });

            // Assert
            Assert.Null(response.Error);
            Assert.Null(response.ErrorDescription);
            Assert.NotNull(response.AccessToken);
            Assert.NotNull(response.Code);
            Assert.NotNull(response.IdToken);
        }

        [Theory]
        [InlineData("code id_token")]
        [InlineData("code id_token token")]
        [InlineData("code token")]
        public async Task InvokeAuthorizationEndpointAsync_CodeResponseTypeCausesAnErrorWhenTokenEndpointIsDisabled(string type)
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.TokenEndpointPath = PathString.Empty;
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(AuthorizationEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                Nonce = "n-0S6_WzA2Mj",
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = type,
                Scope = OpenIdConnectConstants.Scopes.OpenId
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.UnsupportedResponseType, response.Error);
            Assert.Equal("response_type=code is not supported by this server", response.ErrorDescription);
        }

        [Theory]
        [InlineData("id_token")]
        [InlineData("id_token token")]
        [InlineData("token")]
        public async Task InvokeAuthorizationEndpointAsync_MissingCodeResponseTypeCausesAnErrorWhenCodeChallengeIsUsed(string type)
        {
            // Arrange
            var server = CreateAuthorizationServer();

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(AuthorizationEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                CodeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                CodeChallengeMethod = OpenIdConnectConstants.CodeChallengeMethods.Sha256,
                Nonce = "n-0S6_WzA2Mj",
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = type,
                Scope = OpenIdConnectConstants.Scopes.OpenId
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal("The 'code_challenge' and 'code_challenge_method' parameters " +
                         "can only be used with a response type containing 'code'.", response.ErrorDescription);
        }

        [Fact]
        public async Task InvokeAuthorizationEndpointAsync_MissingCodeChallengeCausesAnErrorWhenCodeChallengeMethodIsSpecified()
        {
            // Arrange
            var server = CreateAuthorizationServer();

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(AuthorizationEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                CodeChallengeMethod = OpenIdConnectConstants.CodeChallengeMethods.Sha256,
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = OpenIdConnectConstants.ResponseTypes.Code,
                Scope = OpenIdConnectConstants.Scopes.OpenId
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal("The 'code_challenge_method' parameter " +
                         "cannot be used without 'code_challenge'.", response.ErrorDescription);
        }

        [Fact]
        public async Task InvokeAuthorizationEndpointAsync_InvalidCodeChallengeMethodCausesAnError()
        {
            // Arrange
            var server = CreateAuthorizationServer();

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(AuthorizationEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                CodeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                CodeChallengeMethod = "invalid_code_challenge_method",
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = OpenIdConnectConstants.ResponseTypes.Code,
                Scope = OpenIdConnectConstants.Scopes.OpenId
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal("The specified code_challenge_method is not supported.", response.ErrorDescription);
        }

        [Fact]
        public async Task InvokeAuthorizationEndpointAsync_CodeChallengeMethodDefaultsToPlain()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnValidateAuthorizationRequest = context =>
                {
                    context.Validate();

                    return Task.FromResult(0);
                };

                options.Provider.OnHandleAuthorizationRequest = context =>
                {
                    var identity = new ClaimsIdentity(context.Options.AuthenticationScheme);
                    identity.AddClaim(OpenIdConnectConstants.Claims.Subject, "Bob le Magnifique");

                    var ticket = new AuthenticationTicket(
                        new ClaimsPrincipal(identity),
                        new AuthenticationProperties(),
                        context.Options.AuthenticationScheme);

                    context.Validate(ticket);

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(AuthorizationEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                CodeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = OpenIdConnectConstants.ResponseTypes.Code,
                Scope = OpenIdConnectConstants.Scopes.OpenId
            });

            // Assert
            Assert.NotNull(response.Code);
        }

        [Theory]
        [InlineData("custom_error", null, null)]
        [InlineData("custom_error", "custom_description", null)]
        [InlineData("custom_error", "custom_description", "custom_uri")]
        [InlineData(null, "custom_description", null)]
        [InlineData(null, "custom_description", "custom_uri")]
        [InlineData(null, null, "custom_uri")]
        [InlineData(null, null, null)]
        public async Task InvokeAuthorizationEndpointAsync_ValidateAuthorizationRequest_AllowsRejectingRequest(string error, string description, string uri)
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnValidateAuthorizationRequest = context =>
                {
                    context.Reject(error, description, uri);

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(AuthorizationEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = OpenIdConnectConstants.ResponseTypes.Code,
                Scope = OpenIdConnectConstants.Scopes.OpenId
            });

            // Assert
            Assert.Equal(error ?? OpenIdConnectConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal(description, response.ErrorDescription);
            Assert.Equal(uri, response.ErrorUri);
        }

        [Fact]
        public async Task InvokeAuthorizationEndpointAsync_ValidateAuthorizationRequest_AllowsHandlingResponse()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnValidateAuthorizationRequest = context =>
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
            var response = await client.PostAsync(AuthorizationEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = OpenIdConnectConstants.ResponseTypes.Code,
                Scope = OpenIdConnectConstants.Scopes.OpenId
            });

            // Assert
            Assert.Equal("Bob le Magnifique", (string) response["name"]);
        }

        [Fact]
        public async Task InvokeAuthorizationEndpointAsync_ValidateAuthorizationRequest_AllowsSkippingToNextMiddleware()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnValidateAuthorizationRequest = context =>
                {
                    context.SkipToNextMiddleware();

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(AuthorizationEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = OpenIdConnectConstants.ResponseTypes.Code,
                Scope = OpenIdConnectConstants.Scopes.OpenId
            });

            // Assert
            Assert.Equal("Bob le Magnifique", (string) response["name"]);
        }

        [Fact]
        public async Task InvokeAuthorizationEndpointAsync_ValidateAuthorizationRequest_MissingRedirectUriCausesAnException()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnValidateAuthorizationRequest = context =>
                {
                    context.Validate();

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act and assert
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
            {
                return client.PostAsync(AuthorizationEndpoint, new OpenIdConnectRequest
                {
                    ClientId = "Fabrikam",
                    RedirectUri = null,
                    ResponseType = OpenIdConnectConstants.ResponseTypes.Code
                });
            });

            // Assert
            Assert.Equal("The authorization request cannot be validated because no " +
                         "redirect_uri was specified by the client application.", exception.Message);
        }

        [Fact]
        public async Task InvokeAuthorizationEndpointAsync_ValidateAuthorizationRequest_InvalidRedirectUriCausesAnException()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnValidateAuthorizationRequest = context =>
                {
                    context.Validate("http://www.contoso.com/path");

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act and assert
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
            {
                return client.PostAsync(AuthorizationEndpoint, new OpenIdConnectRequest
                {
                    ClientId = "Fabrikam",
                    RedirectUri = "http://www.fabrikam.com/path",
                    ResponseType = OpenIdConnectConstants.ResponseTypes.Code
                });
            });

            // Assert
            Assert.Equal("The authorization request cannot be validated because a different " +
                         "redirect_uri was specified by the client application.", exception.Message);
        }

        [Theory]
        [InlineData("custom_error", null, null)]
        [InlineData("custom_error", "custom_description", null)]
        [InlineData("custom_error", "custom_description", "custom_uri")]
        [InlineData(null, "custom_description", null)]
        [InlineData(null, "custom_description", "custom_uri")]
        [InlineData(null, null, "custom_uri")]
        [InlineData(null, null, null)]
        public async Task InvokeAuthorizationEndpointAsync_HandleAuthorizationRequest_AllowsRejectingRequest(string error, string description, string uri)
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnValidateAuthorizationRequest = context =>
                {
                    context.Validate();

                    return Task.FromResult(0);
                };

                options.Provider.OnHandleAuthorizationRequest = context =>
                {
                    context.Reject(error, description, uri);

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(AuthorizationEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = OpenIdConnectConstants.ResponseTypes.Code,
                Scope = OpenIdConnectConstants.Scopes.OpenId
            });

            // Assert
            Assert.Equal(error ?? OpenIdConnectConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal(description, response.ErrorDescription);
            Assert.Equal(uri, response.ErrorUri);
        }

        [Fact]
        public async Task InvokeAuthorizationEndpointAsync_HandleAuthorizationRequest_AllowsHandlingResponse()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnValidateAuthorizationRequest = context =>
                {
                    context.Validate();

                    return Task.FromResult(0);
                };

                options.Provider.OnHandleAuthorizationRequest = context =>
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
            var response = await client.PostAsync(AuthorizationEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = OpenIdConnectConstants.ResponseTypes.Code,
                Scope = OpenIdConnectConstants.Scopes.OpenId
            });

            // Assert
            Assert.Equal("Bob le Magnifique", (string) response["name"]);
        }

        [Fact]
        public async Task InvokeAuthorizationEndpointAsync_HandleAuthorizationRequest_AllowsSkippingToNextMiddleware()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnValidateAuthorizationRequest = context =>
                {
                    context.Validate();

                    return Task.FromResult(0);
                };

                options.Provider.OnHandleAuthorizationRequest = context =>
                {
                    context.SkipToNextMiddleware();

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(AuthorizationEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = OpenIdConnectConstants.ResponseTypes.Code,
                Scope = OpenIdConnectConstants.Scopes.OpenId
            });

            // Assert
            Assert.Equal("Bob le Magnifique", (string) response["name"]);
        }

        [Theory]
        [InlineData("code", OpenIdConnectConstants.ResponseModes.Query)]
        [InlineData("code id_token", OpenIdConnectConstants.ResponseModes.Fragment)]
        [InlineData("code id_token token", OpenIdConnectConstants.ResponseModes.Fragment)]
        [InlineData("code token", OpenIdConnectConstants.ResponseModes.Fragment)]
        [InlineData("id_token", OpenIdConnectConstants.ResponseModes.Fragment)]
        [InlineData("id_token token", OpenIdConnectConstants.ResponseModes.Fragment)]
        [InlineData("token", OpenIdConnectConstants.ResponseModes.Fragment)]
        public async Task SendAuthorizationResponseAsync_ResponseModeIsAutomaticallyInferred(string type, string mode)
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnValidateAuthorizationRequest = context =>
                {
                    context.Validate();

                    return Task.FromResult(0);
                };

                options.Provider.OnHandleAuthorizationRequest = context =>
                {
                    var identity = new ClaimsIdentity(context.Options.AuthenticationScheme);
                    identity.AddClaim(OpenIdConnectConstants.Claims.Subject, "Bob le Magnifique");

                    context.Validate(new ClaimsPrincipal(identity));

                    return Task.FromResult(0);
                };

                options.Provider.OnApplyAuthorizationResponse = context =>
                {
                    context.Response["inferred_response_mode"] = context.Response.ResponseMode;

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(AuthorizationEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = type,
                Scope = OpenIdConnectConstants.Scopes.OpenId
            });

            // Assert
            Assert.Equal(mode, (string) response["inferred_response_mode"]);
        }

        [Fact]
        public async Task SendAuthorizationResponseAsync_ApplyAuthorizationResponse_AllowsHandlingResponse()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnValidateAuthorizationRequest = context =>
                {
                    context.Validate();

                    return Task.FromResult(0);
                };

                options.Provider.OnHandleAuthorizationRequest = context =>
                {
                    var identity = new ClaimsIdentity(context.Options.AuthenticationScheme);
                    identity.AddClaim(OpenIdConnectConstants.Claims.Subject, "Bob le Magnifique");

                    context.Validate(new ClaimsPrincipal(identity));

                    return Task.FromResult(0);
                };

                options.Provider.OnApplyAuthorizationResponse = context =>
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
            var response = await client.PostAsync(AuthorizationEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = OpenIdConnectConstants.ResponseTypes.Code,
                Scope = OpenIdConnectConstants.Scopes.OpenId
            });

            // Assert
            Assert.Equal("Bob le Magnifique", (string) response["name"]);
        }

        [Fact]
        public async Task SendAuthorizationResponseAsync_ApplyAuthorizationResponse_ResponseContainsCustomParameters()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnValidateAuthorizationRequest = context =>
                {
                    context.Validate();

                    return Task.FromResult(0);
                };

                options.Provider.OnHandleAuthorizationRequest = context =>
                {
                    var identity = new ClaimsIdentity(context.Options.AuthenticationScheme);
                    identity.AddClaim(OpenIdConnectConstants.Claims.Subject, "Bob le Magnifique");

                    context.Validate(new ClaimsPrincipal(identity));

                    return Task.FromResult(0);
                };

                options.Provider.OnApplyAuthorizationResponse = context =>
                {
                    context.Response["custom_parameter"] = "custom_value";

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(AuthorizationEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = OpenIdConnectConstants.ResponseTypes.Code,
                Scope = OpenIdConnectConstants.Scopes.OpenId
            });

            // Assert
            Assert.Equal("custom_value", (string) response["custom_parameter"]);
        }

        [Fact]
        public async Task SendAuthorizationResponseAsync_ThrowsAnExceptionWhenRequestIsMissing()
        {
            // Note: an exception is only thrown if the request was not properly extracted
            // AND if the developer decided to override the error to return a custom response.
            // To emulate this behavior, the error property is manually set to null.

            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnApplyAuthorizationResponse = context =>
                {
                    context.Response.Error = null;

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act and assert
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
            {
                return client.SendAsync(Put, AuthorizationEndpoint, new OpenIdConnectRequest());
            });

            Assert.Equal("The authorization response cannot be returned.", exception.Message);
        }

        [Fact]
        public async Task SendAuthorizationResponseAsync_UnsupportedResponseModeCausesAnError()
        {
            // Note: response_mode validation is deliberately delayed until an authorization response
            // is returned to allow implementers to override the ApplyAuthorizationResponse event
            // to support custom response modes. To test this scenario, the request is marked
            // as validated and a signin grant is applied to return an authorization response.

            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnValidateAuthorizationRequest = context =>
                {
                    context.Validate();

                    return Task.FromResult(0);
                };

                options.Provider.OnHandleAuthorizationRequest = context =>
                {
                    var identity = new ClaimsIdentity(context.Options.AuthenticationScheme);
                    identity.AddClaim(OpenIdConnectConstants.Claims.Subject, "Bob le Magnifique");

                    context.Validate(new ClaimsPrincipal(identity));

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(AuthorizationEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseMode = "unsupported_response_mode",
                ResponseType = OpenIdConnectConstants.ResponseTypes.Code,
                Scope = OpenIdConnectConstants.Scopes.OpenId
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal("response_mode unsupported", response.ErrorDescription);
        }
    }
}
