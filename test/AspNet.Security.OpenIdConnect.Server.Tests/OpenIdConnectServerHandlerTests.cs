/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.Reflection;
using System.Security.Claims;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Client;
using AspNet.Security.OpenIdConnect.Extensions;
using AspNet.Security.OpenIdConnect.Primitives;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Authentication;
using Microsoft.AspNetCore.Http.Features.Authentication;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Net.Http.Headers;
using Newtonsoft.Json;
using Xunit;

namespace AspNet.Security.OpenIdConnect.Server.Tests {
    public partial class OpenIdConnectServerHandlerTests {
        public const string AuthorizationEndpoint = "/connect/authorize";
        public const string ConfigurationEndpoint = "/.well-known/openid-configuration";
        public const string CryptographyEndpoint = "/.well-known/jwks";
        public const string CustomEndpoint = "/connect/custom";
        public const string IntrospectionEndpoint = "/connect/introspect";
        public const string LogoutEndpoint = "/connect/logout";
        public const string RevocationEndpoint = "/connect/revoke";
        public const string TokenEndpoint = "/connect/token";
        public const string UserinfoEndpoint = "/connect/userinfo";

        [Theory]
        [InlineData(ConfigurationEndpoint)]
        [InlineData(CryptographyEndpoint)]
        [InlineData(CustomEndpoint)]
        [InlineData(AuthorizationEndpoint)]
        [InlineData(IntrospectionEndpoint)]
        [InlineData(LogoutEndpoint)]
        [InlineData(RevocationEndpoint)]
        [InlineData(TokenEndpoint)]
        [InlineData(UserinfoEndpoint)]
        public Task HandleRequestAsync_MatchEndpoint_MatchesCorrespondingEndpoint(string address) {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnMatchEndpoint = context => {
                    // Assert
                    Assert.Equal(context.IsAuthorizationEndpoint, address == AuthorizationEndpoint);
                    Assert.Equal(context.IsConfigurationEndpoint, address == ConfigurationEndpoint);
                    Assert.Equal(context.IsCryptographyEndpoint, address == CryptographyEndpoint);
                    Assert.Equal(context.IsIntrospectionEndpoint, address == IntrospectionEndpoint);
                    Assert.Equal(context.IsLogoutEndpoint, address == LogoutEndpoint);
                    Assert.Equal(context.IsRevocationEndpoint, address == RevocationEndpoint);
                    Assert.Equal(context.IsTokenEndpoint, address == TokenEndpoint);
                    Assert.Equal(context.IsUserinfoEndpoint, address == UserinfoEndpoint);

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            return client.PostAsync(address, new OpenIdConnectRequest());
        }

        [Theory]
        [InlineData("/custom/.well-known/openid-configuration")]
        [InlineData("/custom/.well-known/jwks")]
        [InlineData("/custom/connect/authorize")]
        [InlineData("/custom/connect/custom")]
        [InlineData("/custom/connect/introspect")]
        [InlineData("/custom/connect/logout")]
        [InlineData("/custom/connect/revoke")]
        [InlineData("/custom/connect/token")]
        [InlineData("/custom/connect/userinfo")]
        public Task HandleRequestAsync_MatchEndpoint_AllowsOverridingEndpoint(string address) {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnMatchEndpoint = context => {
                    switch (address) {
                        case "/custom/connect/authorize":
                            context.MatchAuthorizationEndpoint();
                            break;

                        case "/custom/.well-known/openid-configuration":
                            context.MatchConfigurationEndpoint();
                            break;

                        case "/custom/.well-known/jwks":
                            context.MatchCryptographyEndpoint();
                            break;

                        case "/custom/connect/introspect":
                            context.MatchIntrospectionEndpoint();
                            break;

                        case "/custom/connect/logout":
                            context.MatchLogoutEndpoint();
                            break;

                        case "/custom/connect/revoke":
                            context.MatchRevocationEndpoint();
                            break;

                        case "/custom/connect/token":
                            context.MatchTokenEndpoint();
                            break;

                        case "/custom/connect/userinfo":
                            context.MatchUserinfoEndpoint();
                            break;
                    }

                    // Assert
                    Assert.Equal(context.IsAuthorizationEndpoint, address == "/custom/connect/authorize");
                    Assert.Equal(context.IsConfigurationEndpoint, address == "/custom/.well-known/openid-configuration");
                    Assert.Equal(context.IsCryptographyEndpoint, address == "/custom/.well-known/jwks");
                    Assert.Equal(context.IsIntrospectionEndpoint, address == "/custom/connect/introspect");
                    Assert.Equal(context.IsLogoutEndpoint, address == "/custom/connect/logout");
                    Assert.Equal(context.IsRevocationEndpoint, address == "/custom/connect/revoke");
                    Assert.Equal(context.IsTokenEndpoint, address == "/custom/connect/token");
                    Assert.Equal(context.IsUserinfoEndpoint, address == "/custom/connect/userinfo");

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            return client.PostAsync(address, new OpenIdConnectRequest());
        }

        [Theory]
        [InlineData(ConfigurationEndpoint)]
        [InlineData(CryptographyEndpoint)]
        [InlineData(CustomEndpoint)]
        [InlineData(AuthorizationEndpoint)]
        [InlineData(IntrospectionEndpoint)]
        [InlineData(LogoutEndpoint)]
        [InlineData(RevocationEndpoint)]
        [InlineData(TokenEndpoint)]
        [InlineData(UserinfoEndpoint)]
        public async Task HandleRequestAsync_MatchEndpoint_AllowsHandlingResponse(string address) {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnMatchEndpoint = context => {
                    context.HandleResponse();

                    context.HttpContext.Response.Headers[HeaderNames.ContentType] = "application/json";

                    return context.HttpContext.Response.WriteAsync(JsonConvert.SerializeObject(new {
                        name = "Bob le Magnifique"
                    }));
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(address, new OpenIdConnectRequest());

            // Assert
            Assert.Equal("Bob le Magnifique", (string) response["name"]);
        }

        [Theory]
        [InlineData(ConfigurationEndpoint)]
        [InlineData(CryptographyEndpoint)]
        [InlineData(CustomEndpoint)]
        [InlineData(AuthorizationEndpoint)]
        [InlineData(IntrospectionEndpoint)]
        [InlineData(LogoutEndpoint)]
        [InlineData(RevocationEndpoint)]
        [InlineData(TokenEndpoint)]
        [InlineData(UserinfoEndpoint)]
        public async Task HandleRequestAsync_MatchEndpoint_AllowsSkippingToNextMiddleware(string address) {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnMatchEndpoint = context => {
                    context.SkipToNextMiddleware();

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(address, new OpenIdConnectRequest());

            // Assert
            Assert.Equal("Bob le Magnifique", (string) response["name"]);
        }

        [Theory]
        [InlineData(ConfigurationEndpoint)]
        [InlineData(CryptographyEndpoint)]
        [InlineData(AuthorizationEndpoint)]
        [InlineData(IntrospectionEndpoint)]
        [InlineData(LogoutEndpoint)]
        [InlineData(RevocationEndpoint)]
        [InlineData(TokenEndpoint)]
        [InlineData(UserinfoEndpoint)]
        public async Task HandleRequestAsync_RejectsInsecureHttpRequests(string address) {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.AllowInsecureHttp = false;
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(address, new OpenIdConnectRequest());

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal("This server only accepts HTTPS requests.", response.ErrorDescription);
        }

        [Fact]
        public async Task HandleAuthenticateAsync_UnknownEndpointCausesAnException() {
            // Arrange
            var server = CreateAuthorizationServer();

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act and assert
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate {
                return client.PostAsync("/invalid-authenticate", new OpenIdConnectRequest());
            });

            Assert.Equal("An identity cannot be extracted from this request.", exception.Message);
        }

        [Fact]
        public async Task HandleAuthenticateAsync_InvalidEndpointCausesAnException() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.ConfigurationEndpointPath = "/invalid-authenticate";

                options.Provider.OnHandleConfigurationRequest = context => {
                    context.SkipToNextMiddleware();

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act and assert
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate {
                return client.GetAsync("/invalid-authenticate");
            });

            Assert.Equal("An identity cannot be extracted from this request.", exception.Message);
        }

        [Fact]
        public async Task HandleAuthenticateAsync_MissingIdTokenHintReturnsNull() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnHandleLogoutRequest = async context => {
                    var principal = await context.HttpContext.Authentication.AuthenticateAsync(
                        OpenIdConnectServerDefaults.AuthenticationScheme);

                    // Assert
                    Assert.Null(principal);
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.GetAsync(LogoutEndpoint, new OpenIdConnectRequest {
                IdTokenHint = null
            });

            // Assert
            Assert.Equal("Bob le Magnifique", (string) response["name"]);
        }

        [Fact]
        public async Task HandleAuthenticateAsync_InvalidIdTokenHintReturnsNull() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnHandleLogoutRequest = async context => {
                    var principal = await context.HttpContext.Authentication.AuthenticateAsync(
                        OpenIdConnectServerDefaults.AuthenticationScheme);

                    // Assert
                    Assert.Null(principal);
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.GetAsync(LogoutEndpoint, new OpenIdConnectRequest {
                IdTokenHint = "38323A4B-6CB2-41B8-B457-1951987CB383"
            });

            // Assert
            Assert.Equal("Bob le Magnifique", (string) response["name"]);
        }

        [Fact]
        public async Task HandleAuthenticateAsync_ValidIdTokenHintReturnsExpectedIdentity() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnDeserializeIdentityToken = context => {
                    // Assert
                    Assert.Equal("id_token", context.IdentityToken);

                    var identity = new ClaimsIdentity(context.Options.AuthenticationScheme);
                    identity.AddClaim(ClaimTypes.NameIdentifier, "Bob le Magnifique");

                    context.Ticket = new AuthenticationTicket(
                        new ClaimsPrincipal(identity),
                        new AuthenticationProperties(),
                        context.Options.AuthenticationScheme);

                    context.HandleResponse();

                    return Task.FromResult(0);
                };

                options.Provider.OnHandleLogoutRequest = async context => {
                    var principal = await context.HttpContext.Authentication.AuthenticateAsync(
                        OpenIdConnectServerDefaults.AuthenticationScheme);

                    // Assert
                    Assert.NotNull(principal);
                    Assert.Equal("Bob le Magnifique", principal.FindFirst(ClaimTypes.NameIdentifier)?.Value);
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.GetAsync(LogoutEndpoint, new OpenIdConnectRequest {
                IdTokenHint = "id_token"
            });

            // Assert
            Assert.Equal("Bob le Magnifique", (string) response["name"]);
        }

        [Fact]
        public async Task HandleAuthenticateAsync_MissingAuthorizationCodeReturnsNull() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnApplyTokenResponse = async context => {
                    var principal = await context.HttpContext.Authentication.AuthenticateAsync(
                        OpenIdConnectServerDefaults.AuthenticationScheme);

                    // Assert
                    Assert.Null(principal);

                    context.SkipToNextMiddleware();
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest {
                ClientId = "Fabrikam",
                Code = null,
                GrantType = OpenIdConnectConstants.GrantTypes.AuthorizationCode
            });

            // Assert
            Assert.Equal("Bob le Magnifique", (string) response["name"]);
        }

        [Fact]
        public async Task HandleAuthenticateAsync_InvalidAuthorizationCodeReturnsNull() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnValidateTokenRequest = context => {
                    context.Skip();

                    return Task.FromResult(0);
                };

                options.Provider.OnApplyTokenResponse = async context => {
                    var principal = await context.HttpContext.Authentication.AuthenticateAsync(
                        OpenIdConnectServerDefaults.AuthenticationScheme);

                    // Assert
                    Assert.Null(principal);

                    context.SkipToNextMiddleware();
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest {
                ClientId = "Fabrikam",
                Code = "38323A4B-6CB2-41B8-B457-1951987CB383",
                GrantType = OpenIdConnectConstants.GrantTypes.AuthorizationCode
            });

            // Assert
            Assert.Equal("Bob le Magnifique", (string) response["name"]);
        }

        [Fact]
        public async Task HandleAuthenticateAsync_ValidAuthorizationCodeReturnsExpectedIdentity() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnDeserializeAuthorizationCode = context => {
                    // Assert
                    Assert.Equal("authorization_code", context.AuthorizationCode);

                    var identity = new ClaimsIdentity(context.Options.AuthenticationScheme);
                    identity.AddClaim(ClaimTypes.NameIdentifier, "Bob le Magnifique");

                    context.Ticket = new AuthenticationTicket(
                        new ClaimsPrincipal(identity),
                        new AuthenticationProperties(),
                        context.Options.AuthenticationScheme);

                    context.Ticket.SetPresenters("Fabrikam");

                    context.HandleResponse();

                    return Task.FromResult(0);
                };

                options.Provider.OnValidateTokenRequest = context => {
                    context.Skip();

                    return Task.FromResult(0);
                };

                options.Provider.OnHandleTokenRequest = async context => {
                    var principal = await context.HttpContext.Authentication.AuthenticateAsync(
                        OpenIdConnectServerDefaults.AuthenticationScheme);

                    // Assert
                    Assert.NotNull(principal);
                    Assert.Equal("Bob le Magnifique", principal.FindFirst(ClaimTypes.NameIdentifier)?.Value);

                    context.SkipToNextMiddleware();
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest {
                ClientId = "Fabrikam",
                Code = "authorization_code",
                GrantType = OpenIdConnectConstants.GrantTypes.AuthorizationCode
            });

            // Assert
            Assert.Equal("Bob le Magnifique", (string) response["name"]);
        }

        [Fact]
        public async Task HandleAuthenticateAsync_MissingRefreshTokenReturnsNull() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnApplyTokenResponse = async context => {
                    var principal = await context.HttpContext.Authentication.AuthenticateAsync(
                        OpenIdConnectServerDefaults.AuthenticationScheme);

                    // Assert
                    Assert.Null(principal);

                    context.SkipToNextMiddleware();
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest {
                GrantType = OpenIdConnectConstants.GrantTypes.RefreshToken,
                RefreshToken = null
            });

            // Assert
            Assert.Equal("Bob le Magnifique", (string) response["name"]);
        }

        [Fact]
        public async Task HandleAuthenticateAsync_InvalidRefreshTokenReturnsNull() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnValidateTokenRequest = context => {
                    context.Skip();

                    return Task.FromResult(0);
                };

                options.Provider.OnApplyTokenResponse = async context => {
                    var principal = await context.HttpContext.Authentication.AuthenticateAsync(
                        OpenIdConnectServerDefaults.AuthenticationScheme);

                    // Assert
                    Assert.Null(principal);

                    context.SkipToNextMiddleware();
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest {
                GrantType = OpenIdConnectConstants.GrantTypes.RefreshToken,
                RefreshToken = "38323A4B-6CB2-41B8-B457-1951987CB383"
            });

            // Assert
            Assert.Equal("Bob le Magnifique", (string) response["name"]);
        }

        [Fact]
        public async Task HandleAuthenticateAsync_ValidRefreshTokenReturnsExpectedIdentity() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnDeserializeRefreshToken = context => {
                    // Assert
                    Assert.Equal("refresh_token", context.RefreshToken);

                    var identity = new ClaimsIdentity(context.Options.AuthenticationScheme);
                    identity.AddClaim(ClaimTypes.NameIdentifier, "Bob le Magnifique");

                    context.Ticket = new AuthenticationTicket(
                        new ClaimsPrincipal(identity),
                        new AuthenticationProperties(),
                        context.Options.AuthenticationScheme);

                    context.Ticket.SetPresenters("Fabrikam");

                    context.HandleResponse();

                    return Task.FromResult(0);
                };

                options.Provider.OnValidateTokenRequest = context => {
                    context.Skip();

                    return Task.FromResult(0);
                };

                options.Provider.OnHandleTokenRequest = async context => {
                    var principal = await context.HttpContext.Authentication.AuthenticateAsync(
                        OpenIdConnectServerDefaults.AuthenticationScheme);

                    // Assert
                    Assert.NotNull(principal);
                    Assert.Equal("Bob le Magnifique", principal.FindFirst(ClaimTypes.NameIdentifier)?.Value);

                    context.SkipToNextMiddleware();
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest {
                GrantType = OpenIdConnectConstants.GrantTypes.RefreshToken,
                RefreshToken = "refresh_token"
            });

            // Assert
            Assert.Equal("Bob le Magnifique", (string) response["name"]);
        }

        [Fact]
        public async Task HandleSignInAsync_UnknownEndpointCausesAnException() {
            // Arrange
            var server = CreateAuthorizationServer();

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act and assert
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate {
                return client.PostAsync("/invalid-signin", new OpenIdConnectRequest());
            });

            Assert.Equal("An OpenID Connect response cannot be returned from this endpoint.", exception.Message);
        }

        [Fact]
        public async Task HandleSignInAsync_InvalidEndpointCausesAnException() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.ConfigurationEndpointPath = "/invalid-signin";

                options.Provider.OnHandleConfigurationRequest = context => {
                    context.SkipToNextMiddleware();

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act and assert
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate {
                return client.GetAsync("/invalid-signin");
            });

            Assert.Equal("An OpenID Connect response cannot be returned from this endpoint.", exception.Message);
        }

        [Fact]
        public async Task HandleSignInAsync_DuplicateResponseCausesAnException() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnValidateAuthorizationRequest = context => {
                    context.Validate();

                    return Task.FromResult(0);
                };

                options.Provider.OnHandleAuthorizationRequest = async context => {
                    var identity = new ClaimsIdentity(OpenIdConnectServerDefaults.AuthenticationScheme);
                    identity.AddClaim(ClaimTypes.NameIdentifier, "Bob le Bricoleur");

                    var principal = new ClaimsPrincipal(identity);

                    await context.HttpContext.Authentication.SignInAsync(
                        OpenIdConnectServerDefaults.AuthenticationScheme, principal);

                    context.Validate(principal);
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act and assert
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate {
                return client.PostAsync(AuthorizationEndpoint, new OpenIdConnectRequest {
                    ClientId = "Fabrikam",
                    RedirectUri = "http://www.fabrikam.com/path",
                    ResponseType = OpenIdConnectConstants.ResponseTypes.Code
                });
            });

            Assert.Equal("An OpenID Connect response has already been sent.", exception.Message);
        }

        [Fact]
        public async Task HandleSignInAsync_MissingNameIdentifierCausesAnException() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnValidateAuthorizationRequest = context => {
                    context.Validate();

                    return Task.FromResult(0);
                };

                options.Provider.OnHandleAuthorizationRequest = context => {
                    var identity = new ClaimsIdentity(context.Options.AuthenticationScheme);
                    var principal = new ClaimsPrincipal(identity);

                    context.HandleResponse();

                    return context.HttpContext.Authentication.SignInAsync(
                        context.Options.AuthenticationScheme, principal);
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act and assert
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate {
                return client.PostAsync(AuthorizationEndpoint, new OpenIdConnectRequest {
                    ClientId = "Fabrikam",
                    RedirectUri = "http://www.fabrikam.com/path",
                    ResponseType = OpenIdConnectConstants.ResponseTypes.Code,
                    State = "af0ifjsldkj"
                });
            });

            Assert.Equal("The authentication ticket was rejected because it didn't " +
                         "contain the mandatory ClaimTypes.NameIdentifier claim.", exception.Message);
        }

        [Fact]
        public async Task HandleSignInAsync_AuthorizationResponseFlowsState() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnValidateAuthorizationRequest = context => {
                    context.Validate();

                    return Task.FromResult(0);
                };

                options.Provider.OnHandleAuthorizationRequest = context => {
                    var identity = new ClaimsIdentity(context.Options.AuthenticationScheme);
                    identity.AddClaim(ClaimTypes.NameIdentifier, "Bob le Magnifique");

                    var principal = new ClaimsPrincipal(identity);

                    context.HandleResponse();

                    return context.HttpContext.Authentication.SignInAsync(
                        context.Options.AuthenticationScheme, principal);
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(AuthorizationEndpoint, new OpenIdConnectRequest {
                ClientId = "Fabrikam",
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = OpenIdConnectConstants.ResponseTypes.Code,
                State = "af0ifjsldkj"
            });

            // Assert
            Assert.Equal("af0ifjsldkj", response.State);
        }

        [Fact]
        public async Task HandleSignInAsync_ParametersAreCopiedToAuthorizationCode() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnSerializeAuthorizationCode = context => {
                    // Assert
                    Assert.Equal("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                        context.Ticket.GetProperty(OpenIdConnectConstants.Properties.CodeChallenge));

                    Assert.Equal(OpenIdConnectConstants.CodeChallengeMethods.Sha256,
                        context.Ticket.GetProperty(OpenIdConnectConstants.Properties.CodeChallengeMethod));

                    Assert.Equal("n-0S6_WzA2Mj", context.Ticket.GetProperty(OpenIdConnectConstants.Properties.Nonce));

                    Assert.Equal("http://www.fabrikam.com/path",
                        context.Ticket.GetProperty(OpenIdConnectConstants.Properties.RedirectUri));

                    return Task.FromResult(0);
                };

                options.Provider.OnValidateAuthorizationRequest = context => {
                    context.Validate();

                    return Task.FromResult(0);
                };

                options.Provider.OnHandleAuthorizationRequest = context => {
                    var identity = new ClaimsIdentity(context.Options.AuthenticationScheme);
                    identity.AddClaim(ClaimTypes.NameIdentifier, "Bob le Magnifique");

                    context.Validate(new ClaimsPrincipal(identity));

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(AuthorizationEndpoint, new OpenIdConnectRequest {
                ClientId = "Fabrikam",
                CodeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                CodeChallengeMethod = OpenIdConnectConstants.CodeChallengeMethods.Sha256,
                Nonce = "n-0S6_WzA2Mj",
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = OpenIdConnectConstants.ResponseTypes.Code,
                State = "af0ifjsldkj"
            });

            // Assert
            Assert.NotNull(response.Code);
        }

        [Fact]
        public async Task HandleSignInAsync_RefreshTokenIsConfidentialForValidatedRequests() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnSerializeRefreshToken = context => {
                    // Assert
                    Assert.True(context.Ticket.IsConfidential());

                    return Task.FromResult(0);
                };

                options.Provider.OnValidateTokenRequest = context => {
                    context.Validate();

                    return Task.FromResult(0);
                };

                options.Provider.OnHandleTokenRequest = context => {
                    var identity = new ClaimsIdentity(context.Options.AuthenticationScheme);
                    identity.AddClaim(ClaimTypes.NameIdentifier, "Bob le Magnifique");

                    var ticket = new AuthenticationTicket(
                        new ClaimsPrincipal(identity),
                        new AuthenticationProperties(),
                        context.Options.AuthenticationScheme);

                    ticket.SetScopes(OpenIdConnectConstants.Scopes.OfflineAccess);

                    context.Validate(ticket);

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest {
                ClientId = "Fabrikam",
                ClientSecret = "7Fjfp0ZBr1KtDRbnfVdmIw",
                GrantType = OpenIdConnectConstants.GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w",
                Scope = OpenIdConnectConstants.Scopes.OfflineAccess
            });

            // Assert
            Assert.NotNull(response.RefreshToken);
        }

        [Fact]
        public async Task HandleSignInAsync_ScopeDefaultsToOpenId() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnSerializeRefreshToken = context => {
                    // Assert
                    Assert.Equal("openid", context.Ticket.GetProperty(OpenIdConnectConstants.Properties.Scopes));

                    return Task.FromResult(0);
                };

                options.Provider.OnValidateTokenRequest = context => {
                    context.Skip();

                    return Task.FromResult(0);
                };

                options.Provider.OnHandleTokenRequest = context => {
                    var identity = new ClaimsIdentity(context.Options.AuthenticationScheme);
                    identity.AddClaim(ClaimTypes.NameIdentifier, "Bob le Magnifique");

                    context.Validate(new ClaimsPrincipal(identity));

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest {
                GrantType = OpenIdConnectConstants.GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w"
            });
        }

        [Fact]
        public async Task HandleSignInAsync_ResourcesAreInferredFromAudiences() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnSerializeAccessToken = context => {
                    // Assert
                    Assert.Equal("http://www.fabrikam.com/",
                        context.Ticket.GetProperty(OpenIdConnectConstants.Properties.Resources));

                    return Task.FromResult(0);
                };

                options.Provider.OnSerializeRefreshToken = context => {
                    // Assert
                    Assert.Equal("http://www.fabrikam.com/",
                        context.Ticket.GetProperty(OpenIdConnectConstants.Properties.Resources));

                    return Task.FromResult(0);
                };

                options.Provider.OnValidateTokenRequest = context => {
                    context.Skip();

                    return Task.FromResult(0);
                };

                options.Provider.OnHandleTokenRequest = context => {
                    var identity = new ClaimsIdentity(context.Options.AuthenticationScheme);
                    identity.AddClaim(ClaimTypes.NameIdentifier, "Bob le Magnifique");

                    var ticket = new AuthenticationTicket(
                        new ClaimsPrincipal(identity),
                        new AuthenticationProperties(),
                        context.Options.AuthenticationScheme);

                    ticket.SetAudiences("http://www.fabrikam.com/");
                    ticket.SetScopes(OpenIdConnectConstants.Scopes.OfflineAccess);

                    context.Validate(ticket);

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest {
                GrantType = OpenIdConnectConstants.GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w"
            });

            // Assert
            Assert.NotNull(response.AccessToken);
            Assert.NotNull(response.RefreshToken);
        }

        [Theory]
        [InlineData("code")]
        [InlineData("code id_token")]
        [InlineData("code id_token token")]
        [InlineData("code token")]
        public async Task HandleSignInAsync_AnAuthorizationCodeIsReturnedForCodeAndHybridFlowRequests(string type) {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnValidateAuthorizationRequest = context => {
                    context.Validate();

                    return Task.FromResult(0);
                };

                options.Provider.OnHandleAuthorizationRequest = context => {
                    var identity = new ClaimsIdentity(context.Options.AuthenticationScheme);
                    identity.AddClaim(ClaimTypes.NameIdentifier, "Bob le Magnifique");

                    context.Validate(new ClaimsPrincipal(identity));

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(AuthorizationEndpoint, new OpenIdConnectRequest {
                ClientId = "Fabrikam",
                Nonce = "n-0S6_WzA2Mj",
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = type,
                Scope = OpenIdConnectConstants.Scopes.OpenId
            });

            // Assert
            Assert.NotNull(response.Code);
        }

        [Fact]
        public async Task HandleSignInAsync_ResourcesCanBeOverridenForRefreshTokenRequests() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnDeserializeRefreshToken = context => {
                    Assert.Equal("8xLOxBtZp8", context.RefreshToken);

                    var identity = new ClaimsIdentity(context.Options.AuthenticationScheme);
                    identity.AddClaim(ClaimTypes.NameIdentifier, "Bob le Magnifique");

                    context.Ticket = new AuthenticationTicket(
                        new ClaimsPrincipal(identity),
                        new AuthenticationProperties(),
                        context.Options.AuthenticationScheme);

                    context.Ticket.SetResources("http://www.fabrikam.com/", "http://www.contoso.com/");

                    return Task.FromResult(0);
                };

                options.Provider.OnSerializeAccessToken = context => {
                    // Assert
                    Assert.Equal("http://www.fabrikam.com/",
                        context.Ticket.GetProperty(OpenIdConnectConstants.Properties.Resources));

                    return Task.FromResult(0);
                };

                options.Provider.OnValidateTokenRequest = context => {
                    context.Skip();

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest {
                GrantType = OpenIdConnectConstants.GrantTypes.RefreshToken,
                RefreshToken = "8xLOxBtZp8",
                Resource = "http://www.fabrikam.com/"
            });

            // Assert
            Assert.NotNull(response.AccessToken);
        }

        [Fact]
        public async Task HandleSignInAsync_ScopesCanBeOverridenForRefreshTokenRequests() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnDeserializeRefreshToken = context => {
                    Assert.Equal("8xLOxBtZp8", context.RefreshToken);

                    var identity = new ClaimsIdentity(context.Options.AuthenticationScheme);
                    identity.AddClaim(ClaimTypes.NameIdentifier, "Bob le Magnifique");

                    context.Ticket = new AuthenticationTicket(
                        new ClaimsPrincipal(identity),
                        new AuthenticationProperties(),
                        context.Options.AuthenticationScheme);

                    context.Ticket.SetScopes(
                        OpenIdConnectConstants.Scopes.OpenId,
                        OpenIdConnectConstants.Scopes.Phone,
                        OpenIdConnectConstants.Scopes.Profile);

                    return Task.FromResult(0);
                };

                options.Provider.OnSerializeAccessToken = context => {
                    // Assert
                    Assert.Equal(OpenIdConnectConstants.Scopes.Profile,
                        context.Ticket.GetProperty(OpenIdConnectConstants.Properties.Scopes));

                    return Task.FromResult(0);
                };

                options.Provider.OnValidateTokenRequest = context => {
                    context.Skip();

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest {
                GrantType = OpenIdConnectConstants.GrantTypes.RefreshToken,
                RefreshToken = "8xLOxBtZp8",
                Scope = OpenIdConnectConstants.Scopes.Profile
            });

            // Assert
            Assert.NotNull(response.AccessToken);
        }

        [Fact]
        public async Task HandleSignInAsync_ResourcesAreReturnedWhenTheyDifferFromRequestedResources() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnValidateTokenRequest = context => {
                    context.Skip();

                    return Task.FromResult(0);
                };

                options.Provider.OnHandleTokenRequest = context => {
                    var identity = new ClaimsIdentity(context.Options.AuthenticationScheme);
                    identity.AddClaim(ClaimTypes.NameIdentifier, "Bob le Magnifique");

                    var ticket = new AuthenticationTicket(
                        new ClaimsPrincipal(identity),
                        new AuthenticationProperties(),
                        context.Options.AuthenticationScheme);

                    ticket.SetResources("http://www.fabrikam.com/");

                    context.Validate(ticket);

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest {
                GrantType = OpenIdConnectConstants.GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w",
                Resource = "http://www.fabrikam.com/ http://www.contoso.com/"
            });

            // Assert
            Assert.Equal("http://www.fabrikam.com/", response.Resource);
        }

        [Fact]
        public async Task HandleSignInAsync_ScopesAreReturnedWhenTheyDifferFromRequestedScopes() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnValidateTokenRequest = context => {
                    context.Skip();

                    return Task.FromResult(0);
                };

                options.Provider.OnHandleTokenRequest = context => {
                    var identity = new ClaimsIdentity(context.Options.AuthenticationScheme);
                    identity.AddClaim(ClaimTypes.NameIdentifier, "Bob le Magnifique");

                    var ticket = new AuthenticationTicket(
                        new ClaimsPrincipal(identity),
                        new AuthenticationProperties(),
                        context.Options.AuthenticationScheme);

                    ticket.SetScopes(OpenIdConnectConstants.Scopes.Profile);

                    context.Validate(ticket);

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest {
                GrantType = OpenIdConnectConstants.GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w",
                Scope = "openid phone profile"
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Scopes.Profile, response.Scope);
        }

        [Theory]
        [InlineData("code id_token token")]
        [InlineData("code token")]
        [InlineData("id_token token")]
        [InlineData("token")]
        public async Task HandleSignInAsync_AnAccessTokenIsReturnedForImplicitAndHybridFlowRequests(string type) {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnValidateAuthorizationRequest = context => {
                    context.Validate();

                    return Task.FromResult(0);
                };

                options.Provider.OnHandleAuthorizationRequest = context => {
                    var identity = new ClaimsIdentity(context.Options.AuthenticationScheme);
                    identity.AddClaim(ClaimTypes.NameIdentifier, "Bob le Magnifique");

                    context.Validate(new ClaimsPrincipal(identity));

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(AuthorizationEndpoint, new OpenIdConnectRequest {
                ClientId = "Fabrikam",
                Nonce = "n-0S6_WzA2Mj",
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = type,
                Scope = OpenIdConnectConstants.Scopes.OpenId
            });

            // Assert
            Assert.NotNull(response.AccessToken);
        }

        [Fact]
        public async Task HandleSignInAsync_AnAccessTokenIsReturnedForCodeGrantRequests() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnDeserializeAuthorizationCode = context => {
                    Assert.Equal("SplxlOBeZQQYbYS6WxSbIA", context.AuthorizationCode);

                    var identity = new ClaimsIdentity(context.Options.AuthenticationScheme);
                    identity.AddClaim(ClaimTypes.NameIdentifier, "Bob le Magnifique");

                    context.Ticket = new AuthenticationTicket(
                        new ClaimsPrincipal(identity),
                        new AuthenticationProperties(),
                        context.Options.AuthenticationScheme);

                    context.Ticket.SetPresenters("Fabrikam");

                    return Task.FromResult(0);
                };

                options.Provider.OnValidateTokenRequest = context => {
                    context.Skip();

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest {
                ClientId = "Fabrikam",
                Code = "SplxlOBeZQQYbYS6WxSbIA",
                GrantType = OpenIdConnectConstants.GrantTypes.AuthorizationCode
            });

            // Assert
            Assert.NotNull(response.AccessToken);
        }

        [Fact]
        public async Task HandleSignInAsync_AnAccessTokenIsReturnedForRefreshTokenGrantRequests() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnDeserializeRefreshToken = context => {
                    Assert.Equal("8xLOxBtZp8", context.RefreshToken);

                    var identity = new ClaimsIdentity(context.Options.AuthenticationScheme);
                    identity.AddClaim(ClaimTypes.NameIdentifier, "Bob le Magnifique");

                    context.Ticket = new AuthenticationTicket(
                        new ClaimsPrincipal(identity),
                        new AuthenticationProperties(),
                        context.Options.AuthenticationScheme);

                    return Task.FromResult(0);
                };

                options.Provider.OnValidateTokenRequest = context => {
                    context.Skip();

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest {
                GrantType = OpenIdConnectConstants.GrantTypes.RefreshToken,
                RefreshToken = "8xLOxBtZp8"
            });

            // Assert
            Assert.NotNull(response.AccessToken);
        }

        [Fact]
        public async Task HandleSignInAsync_AnAccessTokenIsReturnedForPasswordGrantRequests() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnValidateTokenRequest = context => {
                    context.Skip();

                    return Task.FromResult(0);
                };

                options.Provider.OnHandleTokenRequest = context => {
                    var identity = new ClaimsIdentity(context.Options.AuthenticationScheme);
                    identity.AddClaim(ClaimTypes.NameIdentifier, "Bob le Magnifique");

                    context.Validate(new ClaimsPrincipal(identity));

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest {
                GrantType = OpenIdConnectConstants.GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w"
            });

            // Assert
            Assert.NotNull(response.AccessToken);
        }

        [Fact]
        public async Task HandleSignInAsync_AnAccessTokenIsReturnedForClientCredentialsGrantRequests() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnValidateTokenRequest = context => {
                    context.Validate();

                    return Task.FromResult(0);
                };

                options.Provider.OnHandleTokenRequest = context => {
                    var identity = new ClaimsIdentity(context.Options.AuthenticationScheme);
                    identity.AddClaim(ClaimTypes.NameIdentifier, "Fabrikam");

                    context.Validate(new ClaimsPrincipal(identity));

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest {
                ClientId = "Fabrikam",
                ClientSecret = "7Fjfp0ZBr1KtDRbnfVdmIw",
                GrantType = OpenIdConnectConstants.GrantTypes.ClientCredentials,
            });

            // Assert
            Assert.NotNull(response.AccessToken);
        }

        [Fact]
        public async Task HandleSignInAsync_AnAccessTokenIsReturnedForCustomGrantRequests() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnValidateTokenRequest = context => {
                    context.Skip();

                    return Task.FromResult(0);
                };

                options.Provider.OnHandleTokenRequest = context => {
                    var identity = new ClaimsIdentity(context.Options.AuthenticationScheme);
                    identity.AddClaim(ClaimTypes.NameIdentifier, "Bob le Magnifique");

                    context.Validate(new ClaimsPrincipal(identity));

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest {
                GrantType = "urn:ietf:params:oauth:grant-type:custom_grant"
            });

            // Assert
            Assert.NotNull(response.AccessToken);
        }

        [Fact]
        public async Task HandleSignInAsync_ExpiresInIsReturnedWhenExpirationDateIsKnown() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnValidateTokenRequest = context => {
                    context.Skip();

                    return Task.FromResult(0);
                };

                options.Provider.OnHandleTokenRequest = context => {
                    var identity = new ClaimsIdentity(context.Options.AuthenticationScheme);
                    identity.AddClaim(ClaimTypes.NameIdentifier, "Bob le Magnifique");

                    context.Validate(new ClaimsPrincipal(identity));

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest {
                GrantType = OpenIdConnectConstants.GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w"
            });

            // Assert
            Assert.NotNull(response.ExpiresIn);
        }

        [Fact]
        public async Task HandleSignInAsync_NoRefreshTokenIsReturnedWhenOfflineAccessScopeIsNotGranted() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnValidateTokenRequest = context => {
                    context.Skip();

                    return Task.FromResult(0);
                };

                options.Provider.OnHandleTokenRequest = context => {
                    var identity = new ClaimsIdentity(context.Options.AuthenticationScheme);
                    identity.AddClaim(ClaimTypes.NameIdentifier, "Bob le Magnifique");

                    context.Validate(new ClaimsPrincipal(identity));

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest {
                GrantType = OpenIdConnectConstants.GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w"
            });

            // Assert
            Assert.Null(response.RefreshToken);
        }

        [Fact]
        public async Task HandleSignInAsync_ARefreshTokenIsReturnedForCodeGrantRequests() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnDeserializeAuthorizationCode = context => {
                    Assert.Equal("SplxlOBeZQQYbYS6WxSbIA", context.AuthorizationCode);

                    var identity = new ClaimsIdentity(context.Options.AuthenticationScheme);
                    identity.AddClaim(ClaimTypes.NameIdentifier, "Bob le Magnifique");

                    context.Ticket = new AuthenticationTicket(
                        new ClaimsPrincipal(identity),
                        new AuthenticationProperties(),
                        context.Options.AuthenticationScheme);

                    context.Ticket.SetPresenters("Fabrikam");
                    context.Ticket.SetScopes(OpenIdConnectConstants.Scopes.OfflineAccess);

                    return Task.FromResult(0);
                };

                options.Provider.OnValidateTokenRequest = context => {
                    context.Skip();

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest {
                ClientId = "Fabrikam",
                Code = "SplxlOBeZQQYbYS6WxSbIA",
                GrantType = OpenIdConnectConstants.GrantTypes.AuthorizationCode
            });

            // Assert
            Assert.NotNull(response.RefreshToken);
        }

        [Fact]
        public async Task HandleSignInAsync_ARefreshTokenIsReturnedForRefreshTokenGrantRequests() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnDeserializeRefreshToken = context => {
                    Assert.Equal("8xLOxBtZp8", context.RefreshToken);

                    var identity = new ClaimsIdentity(context.Options.AuthenticationScheme);
                    identity.AddClaim(ClaimTypes.NameIdentifier, "Bob le Magnifique");

                    context.Ticket = new AuthenticationTicket(
                        new ClaimsPrincipal(identity),
                        new AuthenticationProperties(),
                        context.Options.AuthenticationScheme);

                    context.Ticket.SetScopes(OpenIdConnectConstants.Scopes.OfflineAccess);

                    return Task.FromResult(0);
                };

                options.Provider.OnValidateTokenRequest = context => {
                    context.Skip();

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest {
                GrantType = OpenIdConnectConstants.GrantTypes.RefreshToken,
                RefreshToken = "8xLOxBtZp8"
            });

            // Assert
            Assert.NotNull(response.RefreshToken);
        }

        [Fact]
        public async Task HandleSignInAsync_NoRefreshTokenIsReturnedWhenSlidingExpirationIsDisabled() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.UseSlidingExpiration = false;

                options.Provider.OnDeserializeRefreshToken = context => {
                    Assert.Equal("8xLOxBtZp8", context.RefreshToken);

                    var identity = new ClaimsIdentity(context.Options.AuthenticationScheme);
                    identity.AddClaim(ClaimTypes.NameIdentifier, "Bob le Magnifique");

                    context.Ticket = new AuthenticationTicket(
                        new ClaimsPrincipal(identity),
                        new AuthenticationProperties(),
                        context.Options.AuthenticationScheme);

                    context.Ticket.SetScopes(OpenIdConnectConstants.Scopes.OfflineAccess);

                    return Task.FromResult(0);
                };

                options.Provider.OnValidateTokenRequest = context => {
                    context.Skip();

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest {
                GrantType = OpenIdConnectConstants.GrantTypes.RefreshToken,
                RefreshToken = "8xLOxBtZp8"
            });

            // Assert
            Assert.Null(response.RefreshToken);
        }

        [Fact]
        public async Task HandleSignInAsync_ARefreshTokenIsReturnedForPasswordGrantRequests() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnValidateTokenRequest = context => {
                    context.Skip();

                    return Task.FromResult(0);
                };

                options.Provider.OnHandleTokenRequest = context => {
                    var identity = new ClaimsIdentity(context.Options.AuthenticationScheme);
                    identity.AddClaim(ClaimTypes.NameIdentifier, "Bob le Magnifique");

                    var ticket = new AuthenticationTicket(
                        new ClaimsPrincipal(identity),
                        new AuthenticationProperties(),
                        context.Options.AuthenticationScheme);

                    ticket.SetScopes(OpenIdConnectConstants.Scopes.OfflineAccess);

                    context.Validate(ticket);

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest {
                GrantType = OpenIdConnectConstants.GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w"
            });

            // Assert
            Assert.NotNull(response.RefreshToken);
        }

        [Fact]
        public async Task HandleSignInAsync_ARefreshTokenIsReturnedForClientCredentialsGrantRequests() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnValidateTokenRequest = context => {
                    context.Validate();

                    return Task.FromResult(0);
                };

                options.Provider.OnHandleTokenRequest = context => {
                    var identity = new ClaimsIdentity(context.Options.AuthenticationScheme);
                    identity.AddClaim(ClaimTypes.NameIdentifier, "Fabrikam");

                    var ticket = new AuthenticationTicket(
                        new ClaimsPrincipal(identity),
                        new AuthenticationProperties(),
                        context.Options.AuthenticationScheme);

                    ticket.SetScopes(OpenIdConnectConstants.Scopes.OfflineAccess);

                    context.Validate(ticket);

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest {
                ClientId = "Fabrikam",
                ClientSecret = "7Fjfp0ZBr1KtDRbnfVdmIw",
                GrantType = OpenIdConnectConstants.GrantTypes.ClientCredentials,
            });

            // Assert
            Assert.NotNull(response.RefreshToken);
        }

        [Fact]
        public async Task HandleSignInAsync_ARefreshTokenIsReturnedForCustomGrantRequests() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnValidateTokenRequest = context => {
                    context.Skip();

                    return Task.FromResult(0);
                };

                options.Provider.OnHandleTokenRequest = context => {
                    var identity = new ClaimsIdentity(context.Options.AuthenticationScheme);
                    identity.AddClaim(ClaimTypes.NameIdentifier, "Bob le Magnifique");

                    var ticket = new AuthenticationTicket(
                        new ClaimsPrincipal(identity),
                        new AuthenticationProperties(),
                        context.Options.AuthenticationScheme);

                    ticket.SetScopes(OpenIdConnectConstants.Scopes.OfflineAccess);

                    context.Validate(ticket);

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest {
                GrantType = "urn:ietf:params:oauth:grant-type:custom_grant"
            });

            // Assert
            Assert.NotNull(response.RefreshToken);
        }

        [Fact]
        public async Task HandleSignInAsync_NoIdentityTokenIsReturnedWhenOfflineAccessScopeIsNotGranted() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnValidateTokenRequest = context => {
                    context.Skip();

                    return Task.FromResult(0);
                };

                options.Provider.OnHandleTokenRequest = context => {
                    var identity = new ClaimsIdentity(context.Options.AuthenticationScheme);
                    identity.AddClaim(ClaimTypes.NameIdentifier, "Bob le Magnifique");

                    context.Validate(new ClaimsPrincipal(identity));

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest {
                GrantType = OpenIdConnectConstants.GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w"
            });

            // Assert
            Assert.Null(response.IdToken);
        }

        [Theory]
        [InlineData("code id_token")]
        [InlineData("code id_token token")]
        [InlineData("id_token")]
        [InlineData("id_token token")]
        public async Task HandleSignInAsync_AnIdentityTokenIsReturnedForImplicitAndHybridFlowRequests(string type) {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnValidateAuthorizationRequest = context => {
                    context.Validate();

                    return Task.FromResult(0);
                };

                options.Provider.OnHandleAuthorizationRequest = context => {
                    var identity = new ClaimsIdentity(context.Options.AuthenticationScheme);
                    identity.AddClaim(ClaimTypes.NameIdentifier, "Bob le Magnifique");

                    context.Validate(new ClaimsPrincipal(identity));

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(AuthorizationEndpoint, new OpenIdConnectRequest {
                ClientId = "Fabrikam",
                Nonce = "n-0S6_WzA2Mj",
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = type,
                Scope = OpenIdConnectConstants.Scopes.OpenId
            });

            // Assert
            Assert.NotNull(response.IdToken);
        }

        [Fact]
        public async Task HandleSignInAsync_AnIdentityTokenIsReturnedForCodeGrantRequests() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnDeserializeAuthorizationCode = context => {
                    Assert.Equal("SplxlOBeZQQYbYS6WxSbIA", context.AuthorizationCode);

                    var identity = new ClaimsIdentity(context.Options.AuthenticationScheme);
                    identity.AddClaim(ClaimTypes.NameIdentifier, "Bob le Magnifique");

                    context.Ticket = new AuthenticationTicket(
                        new ClaimsPrincipal(identity),
                        new AuthenticationProperties(),
                        context.Options.AuthenticationScheme);

                    context.Ticket.SetPresenters("Fabrikam");
                    context.Ticket.SetScopes(OpenIdConnectConstants.Scopes.OpenId);

                    return Task.FromResult(0);
                };

                options.Provider.OnValidateTokenRequest = context => {
                    context.Skip();

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest {
                ClientId = "Fabrikam",
                Code = "SplxlOBeZQQYbYS6WxSbIA",
                GrantType = OpenIdConnectConstants.GrantTypes.AuthorizationCode
            });

            // Assert
            Assert.NotNull(response.IdToken);
        }

        [Fact]
        public async Task HandleSignInAsync_AnIdentityTokenIsReturnedForRefreshTokenGrantRequests() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnDeserializeRefreshToken = context => {
                    Assert.Equal("8xLOxBtZp8", context.RefreshToken);

                    var identity = new ClaimsIdentity(context.Options.AuthenticationScheme);
                    identity.AddClaim(ClaimTypes.NameIdentifier, "Bob le Magnifique");

                    context.Ticket = new AuthenticationTicket(
                        new ClaimsPrincipal(identity),
                        new AuthenticationProperties(),
                        context.Options.AuthenticationScheme);

                    context.Ticket.SetScopes(OpenIdConnectConstants.Scopes.OpenId);

                    return Task.FromResult(0);
                };

                options.Provider.OnValidateTokenRequest = context => {
                    context.Skip();

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest {
                GrantType = OpenIdConnectConstants.GrantTypes.RefreshToken,
                RefreshToken = "8xLOxBtZp8"
            });

            // Assert
            Assert.NotNull(response.IdToken);
        }

        [Fact]
        public async Task HandleSignInAsync_AnIdentityTokenIsReturnedForPasswordGrantRequests() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnValidateTokenRequest = context => {
                    context.Skip();

                    return Task.FromResult(0);
                };

                options.Provider.OnHandleTokenRequest = context => {
                    var identity = new ClaimsIdentity(context.Options.AuthenticationScheme);
                    identity.AddClaim(ClaimTypes.NameIdentifier, "Bob le Magnifique");

                    context.Validate(new ClaimsPrincipal(identity));

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest {
                GrantType = OpenIdConnectConstants.GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w",
                Scope = OpenIdConnectConstants.Scopes.OpenId
            });

            // Assert
            Assert.NotNull(response.IdToken);
        }

        [Fact]
        public async Task HandleSignInAsync_AnIdentityTokenIsReturnedForClientCredentialsGrantRequests() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnValidateTokenRequest = context => {
                    context.Validate();

                    return Task.FromResult(0);
                };

                options.Provider.OnHandleTokenRequest = context => {
                    var identity = new ClaimsIdentity(context.Options.AuthenticationScheme);
                    identity.AddClaim(ClaimTypes.NameIdentifier, "Fabrikam");

                    context.Validate(new ClaimsPrincipal(identity));

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest {
                ClientId = "Fabrikam",
                ClientSecret = "7Fjfp0ZBr1KtDRbnfVdmIw",
                GrantType = OpenIdConnectConstants.GrantTypes.ClientCredentials,
                Scope = OpenIdConnectConstants.Scopes.OpenId
            });

            // Assert
            Assert.NotNull(response.IdToken);
        }

        [Fact]
        public async Task HandleSignInAsync_AnIdentityTokenIsReturnedForCustomGrantRequests() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnValidateTokenRequest = context => {
                    context.Skip();

                    return Task.FromResult(0);
                };

                options.Provider.OnHandleTokenRequest = context => {
                    var identity = new ClaimsIdentity(context.Options.AuthenticationScheme);
                    identity.AddClaim(ClaimTypes.NameIdentifier, "Bob le Magnifique");

                    context.Validate(new ClaimsPrincipal(identity));

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest {
                GrantType = "urn:ietf:params:oauth:grant-type:custom_grant",
                Scope = OpenIdConnectConstants.Scopes.OpenId
            });

            // Assert
            Assert.NotNull(response.IdToken);
        }

        [Fact]
        public async Task HandleSignOutAsync_InvalidEndpointCausesAnException() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.ConfigurationEndpointPath = "/invalid-signout";

                options.Provider.OnHandleConfigurationRequest = context => {
                    context.SkipToNextMiddleware();

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act and assert
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate {
                return client.GetAsync("/invalid-signout");
            });

            Assert.Equal("An OpenID Connect response cannot be returned from this endpoint.", exception.Message);
        }

        [Fact]
        public async Task HandleSignOutAsync_DuplicateResponseCausesAnException() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnHandleLogoutRequest = async context => {
                    await context.HttpContext.Authentication.SignOutAsync(
                        OpenIdConnectServerDefaults.AuthenticationScheme);

                    await context.HttpContext.Authentication.SignOutAsync(
                        OpenIdConnectServerDefaults.AuthenticationScheme);

                    context.HandleResponse();
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act and assert
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate {
                return client.PostAsync(LogoutEndpoint, new OpenIdConnectRequest());
            });

            Assert.Equal("An OpenID Connect response has already been sent.", exception.Message);
        }

        [Fact]
        public async Task HandleSignOutAsync_LogoutResponseFlowsState() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnValidateLogoutRequest = context => {
                    context.Validate();

                    return Task.FromResult(0);
                };

                options.Provider.OnHandleLogoutRequest = context => {
                    context.HandleResponse();

                    return context.HttpContext.Authentication.SignOutAsync(context.Options.AuthenticationScheme);
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(LogoutEndpoint, new OpenIdConnectRequest {
                PostLogoutRedirectUri = "http://www.fabrikam.com/path",
                State = "af0ifjsldkj"
            });

            // Assert
            Assert.Equal("af0ifjsldkj", response.State);
        }

        [Fact]
        public async Task HandleUnauthorizedAsync_InvalidEndpointCausesAnException() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.ConfigurationEndpointPath = "/invalid-challenge";

                options.Provider.OnHandleConfigurationRequest = context => {
                    context.SkipToNextMiddleware();

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act and assert
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate {
                return client.GetAsync("/invalid-challenge");
            });

            Assert.Equal("An OpenID Connect response cannot be returned from this endpoint.", exception.Message);
        }

        [Fact]
        public async Task HandleUnauthorizedAsync_DuplicateResponseCausesAnException() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnValidateAuthorizationRequest = context => {
                    context.Validate();

                    return Task.FromResult(0);
                };

                options.Provider.OnHandleAuthorizationRequest = async context => {
                    await context.HttpContext.Authentication.ForbidAsync(
                        OpenIdConnectServerDefaults.AuthenticationScheme);

                    await context.HttpContext.Authentication.ChallengeAsync(
                        OpenIdConnectServerDefaults.AuthenticationScheme);

                    context.HandleResponse();
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act and assert
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate {
                return client.PostAsync(AuthorizationEndpoint, new OpenIdConnectRequest {
                    ClientId = "Fabrikam",
                    RedirectUri = "http://www.fabrikam.com/path",
                    ResponseType = OpenIdConnectConstants.ResponseTypes.Code
                });
            });

            Assert.Equal("An OpenID Connect response has already been sent.", exception.Message);
        }

        [Fact]
        public async Task HandleUnauthorizedAsync_AuthorizationResponseFlowsState() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnValidateAuthorizationRequest = context => {
                    context.Validate();

                    return Task.FromResult(0);
                };

                options.Provider.OnHandleAuthorizationRequest = context => {
                    context.HandleResponse();

                    return context.HttpContext.Authentication.ChallengeAsync(context.Options.AuthenticationScheme);
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(AuthorizationEndpoint, new OpenIdConnectRequest {
                ClientId = "Fabrikam",
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = OpenIdConnectConstants.ResponseTypes.Code,
                State = "af0ifjsldkj"
            });

            // Assert
            Assert.Equal("af0ifjsldkj", response.State);
            Assert.Equal(OpenIdConnectConstants.Errors.AccessDenied, response.Error);
            Assert.Equal("The authorization grant has been denied by the resource owner.", response.ErrorDescription);
        }

        private static TestServer CreateAuthorizationServer(Action<OpenIdConnectServerOptions> configuration = null) {
            var builder = new WebHostBuilder();

            builder.UseEnvironment("Testing");

            builder.ConfigureServices(services => services.AddAuthentication());

            builder.Configure(app => {
                app.UseCookieAuthentication(new CookieAuthenticationOptions {
                    AutomaticAuthenticate = true,
                    AutomaticChallenge = true,
                    LoginPath = "/login",
                    LogoutPath = "/logout"
                });

                app.UseOpenIdConnectServer(options => {
                    options.AllowInsecureHttp = true;

                    // Enable the tested endpoints.
                    options.AuthorizationEndpointPath = AuthorizationEndpoint;
                    options.IntrospectionEndpointPath = IntrospectionEndpoint;
                    options.LogoutEndpointPath = LogoutEndpoint;
                    options.RevocationEndpointPath = RevocationEndpoint;
                    options.TokenEndpointPath = TokenEndpoint;
                    options.UserinfoEndpointPath = UserinfoEndpoint;

                    options.SigningCredentials.AddCertificate(
                        assembly: typeof(OpenIdConnectServerMiddlewareTests).GetTypeInfo().Assembly,
                        resource: "AspNet.Security.OpenIdConnect.Server.Tests.Certificate.pfx",
                        password: "Owin.Security.OpenIdConnect.Server");

                    // Note: overriding the default data protection provider is not necessary for the tests to pass,
                    // but is useful to ensure unnecessary keys are not persisted in testing environments, which also
                    // helps make the unit tests run faster, as no registry or disk access is required in this case.
                    options.DataProtectionProvider = new EphemeralDataProtectionProvider(app.ApplicationServices);

                    // Run the configuration delegate
                    // registered by the unit tests.
                    configuration?.Invoke(options);
                });

                app.Use(next => context => {
                    if (context.Request.Path == "/invalid-signin") {
                        var identity = new ClaimsIdentity(OpenIdConnectServerDefaults.AuthenticationScheme);
                        identity.AddClaim(ClaimTypes.NameIdentifier, "Bob le Bricoleur");

                        var principal = new ClaimsPrincipal(identity);

                        return context.Authentication.SignInAsync(OpenIdConnectServerDefaults.AuthenticationScheme, principal);
                    }

                    else if (context.Request.Path == "/invalid-signout") {
                        return context.Authentication.SignOutAsync(OpenIdConnectServerDefaults.AuthenticationScheme);
                    }

                    else if (context.Request.Path == "/invalid-challenge") {
                        return context.Authentication.ChallengeAsync(
                            OpenIdConnectServerDefaults.AuthenticationScheme,
                            new AuthenticationProperties(),
                            ChallengeBehavior.Unauthorized);
                    }

                    else if (context.Request.Path == "/invalid-authenticate") {
                        return context.Authentication.AuthenticateAsync(OpenIdConnectServerDefaults.AuthenticationScheme);
                    }

                    return next(context);
                });

                app.Run(context => {
                    context.Response.Headers[HeaderNames.ContentType] = "application/json";

                    return context.Response.WriteAsync(JsonConvert.SerializeObject(new {
                        name = "Bob le Magnifique"
                    }));
                });
            });

            return new TestServer(builder);
        }
    }
}
