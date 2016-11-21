using System;
using System.IdentityModel.Tokens;
using System.Security.Claims;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Client;
using AspNet.Security.OpenIdConnect.Primitives;
using Microsoft.Owin.Security;
using Moq;
using Owin.Security.OpenIdConnect.Extensions;
using Xunit;

namespace Owin.Security.OpenIdConnect.Server.Tests {
    public partial class OpenIdConnectServerHandlerTests {
        [Fact]
        public async Task SerializeAuthorizationCodeAsync_ExpirationDateIsInferredFromCurrentDatetime() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnSerializeAuthorizationCode = context => {
                    // Assert
                    Assert.NotNull(context.Ticket.Properties.IssuedUtc);
                    Assert.NotNull(context.Ticket.Properties.ExpiresUtc);

                    Assert.Equal(context.Ticket.Properties.IssuedUtc +
                                 context.Options.AuthorizationCodeLifetime,
                        context.Ticket.Properties.ExpiresUtc);

                    return Task.FromResult(0);
                };

                options.Provider.OnValidateAuthorizationRequest = context => {
                    context.Validate();

                    return Task.FromResult(0);
                };

                options.Provider.OnHandleAuthorizationRequest = context => {
                    var identity = new ClaimsIdentity(context.Options.AuthenticationType);
                    identity.AddClaim(ClaimTypes.NameIdentifier, "Bob le Magnifique");

                    context.Validate(identity);

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(AuthorizationEndpoint, new OpenIdConnectRequest {
                ClientId = "Fabrikam",
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = OpenIdConnectConstants.ResponseTypes.Code,
                Scope = OpenIdConnectConstants.Scopes.OpenId
            });

            // Assert
            Assert.NotNull(response.Code);
        }

        [Fact]
        public async Task SerializeAuthorizationCodeAsync_BasicPropertiesAreAutomaticallyAdded() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnSerializeAuthorizationCode = context => {
                    // Assert
                    Assert.Equal(OpenIdConnectConstants.Usages.AuthorizationCode, context.Ticket.GetUsage());
                    Assert.Equal("Fabrikam", context.Ticket.GetProperty(OpenIdConnectConstants.Properties.Presenters));
                    Assert.NotNull(context.Ticket.GetTicketId());

                    return Task.FromResult(0);
                };

                options.Provider.OnValidateAuthorizationRequest = context => {
                    context.Validate();

                    return Task.FromResult(0);
                };

                options.Provider.OnHandleAuthorizationRequest = context => {
                    var identity = new ClaimsIdentity(context.Options.AuthenticationType);
                    identity.AddClaim(ClaimTypes.NameIdentifier, "Bob le Magnifique");

                    context.Validate(identity);

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(AuthorizationEndpoint, new OpenIdConnectRequest {
                ClientId = "Fabrikam",
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = OpenIdConnectConstants.ResponseTypes.Code,
                Scope = OpenIdConnectConstants.Scopes.OpenId
            });

            // Assert
            Assert.NotNull(response.Code);
        }

        [Fact]
        public async Task SerializeAuthorizationCodeAsync_AllowsHandlingSerialization() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnSerializeAuthorizationCode = context => {
                    context.AuthorizationCode = "authorization_code";
                    context.HandleResponse();

                    return Task.FromResult(0);
                };

                options.Provider.OnValidateAuthorizationRequest = context => {
                    context.Validate();

                    return Task.FromResult(0);
                };

                options.Provider.OnHandleAuthorizationRequest = context => {
                    var identity = new ClaimsIdentity(context.Options.AuthenticationType);
                    identity.AddClaim(ClaimTypes.NameIdentifier, "Bob le Magnifique");

                    context.Validate(identity);

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(AuthorizationEndpoint, new OpenIdConnectRequest {
                ClientId = "Fabrikam",
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = OpenIdConnectConstants.ResponseTypes.Code,
                Scope = OpenIdConnectConstants.Scopes.OpenId
            });

            // Assert
            Assert.Equal("authorization_code", response.Code);
        }

        [Fact]
        public async Task SerializeAuthorizationCodeAsync_AllowsSkippingSerialization() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnSerializeAuthorizationCode = context => {
                    context.SkipToNextMiddleware();

                    return Task.FromResult(0);
                };

                options.Provider.OnValidateAuthorizationRequest = context => {
                    context.Validate();

                    return Task.FromResult(0);
                };

                options.Provider.OnHandleAuthorizationRequest = context => {
                    var identity = new ClaimsIdentity(context.Options.AuthenticationType);
                    identity.AddClaim(ClaimTypes.NameIdentifier, "Bob le Magnifique");

                    context.Validate(identity);

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(AuthorizationEndpoint, new OpenIdConnectRequest {
                ClientId = "Fabrikam",
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = OpenIdConnectConstants.ResponseTypes.Code,
                Scope = OpenIdConnectConstants.Scopes.OpenId
            });

            // Assert
            Assert.Null(response.Code);
        }

        [Fact]
        public async Task SerializeAuthorizationCodeAsync_UsesAuthorizationCodeFormat() {
            // Arrange
            var format = new Mock<ISecureDataFormat<AuthenticationTicket>>();
            format.Setup(mock => mock.Protect(It.IsAny<AuthenticationTicket>()))
                .Returns("7F82F1A3-8C9F-489F-B838-4B644B7C92B2")
                .Verifiable();

            var server = CreateAuthorizationServer(options => {
                options.AuthorizationCodeFormat = format.Object;

                options.Provider.OnValidateAuthorizationRequest = context => {
                    context.Validate();

                    return Task.FromResult(0);
                };

                options.Provider.OnHandleAuthorizationRequest = context => {
                    var identity = new ClaimsIdentity(context.Options.AuthenticationType);
                    identity.AddClaim(ClaimTypes.NameIdentifier, "Bob le Magnifique");

                    context.Validate(identity);

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(AuthorizationEndpoint, new OpenIdConnectRequest {
                ClientId = "Fabrikam",
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = OpenIdConnectConstants.ResponseTypes.Code,
                Scope = OpenIdConnectConstants.Scopes.OpenId
            });

            // Assert
            Assert.Equal("7F82F1A3-8C9F-489F-B838-4B644B7C92B2", response.Code);
            format.Verify(mock => mock.Protect(It.IsAny<AuthenticationTicket>()), Times.Once());
        }

        [Fact]
        public async Task SerializeAccessTokenAsync_ExpirationDateIsInferredFromCurrentDatetime() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnSerializeAccessToken = context => {
                    // Assert
                    Assert.NotNull(context.Ticket.Properties.IssuedUtc);
                    Assert.NotNull(context.Ticket.Properties.ExpiresUtc);

                    Assert.Equal(context.Ticket.Properties.IssuedUtc +
                                 context.Options.AccessTokenLifetime,
                        context.Ticket.Properties.ExpiresUtc);

                    return Task.FromResult(0);
                };

                options.Provider.OnValidateTokenRequest = context => {
                    context.Skip();

                    return Task.FromResult(0);
                };

                options.Provider.OnHandleTokenRequest = context => {
                    var identity = new ClaimsIdentity(context.Options.AuthenticationType);
                    identity.AddClaim(ClaimTypes.NameIdentifier, "Bob le Magnifique");

                    context.Validate(identity);

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

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
        public async Task SerializeAccessTokenAsync_ClaimsWithoutAppropriateDestinationAreIgnored() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnSerializeAccessToken = context => {
                    // Assert
                    Assert.Null(context.Ticket.Identity.GetClaim(ClaimTypes.GivenName));

                    return Task.FromResult(0);
                };

                options.Provider.OnValidateTokenRequest = context => {
                    context.Skip();

                    return Task.FromResult(0);
                };

                options.Provider.OnHandleTokenRequest = context => {
                    var identity = new ClaimsIdentity(context.Options.AuthenticationType);
                    identity.AddClaim(ClaimTypes.NameIdentifier, "Bob le Magnifique");
                    identity.AddClaim(ClaimTypes.GivenName, "Bob");

                    context.Validate(identity);

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

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
        public async Task SerializeAccessTokenAsync_ClaimsWithAppropriateDestinationAreIncluded() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnSerializeAccessToken = context => {
                    // Assert
                    Assert.Equal("Bob", context.Ticket.Identity.GetClaim(ClaimTypes.GivenName));

                    return Task.FromResult(0);
                };

                options.Provider.OnValidateTokenRequest = context => {
                    context.Skip();

                    return Task.FromResult(0);
                };

                options.Provider.OnHandleTokenRequest = context => {
                    var identity = new ClaimsIdentity(context.Options.AuthenticationType);
                    identity.AddClaim(ClaimTypes.NameIdentifier, "Bob le Magnifique");
                    identity.AddClaim(ClaimTypes.GivenName, "Bob", OpenIdConnectConstants.Destinations.AccessToken);

                    context.Validate(identity);

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

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
        public async Task SerializeAccessTokenAsync_BasicPropertiesAreAutomaticallyAdded() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnSerializeAccessToken = context => {
                    // Assert
                    Assert.Equal(OpenIdConnectConstants.Usages.AccessToken, context.Ticket.GetUsage());
                    Assert.Equal("Fabrikam", context.Ticket.GetProperty(OpenIdConnectConstants.Properties.Presenters));
                    Assert.NotNull(context.Ticket.GetTicketId());

                    return Task.FromResult(0);
                };

                options.Provider.OnValidateTokenRequest = context => {
                    context.Skip();

                    return Task.FromResult(0);
                };

                options.Provider.OnHandleTokenRequest = context => {
                    var identity = new ClaimsIdentity(context.Options.AuthenticationType);
                    identity.AddClaim(ClaimTypes.NameIdentifier, "Bob le Magnifique");

                    context.Validate(identity);

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest {
                ClientId = "Fabrikam",
                GrantType = OpenIdConnectConstants.GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w"
            });

            // Assert
            Assert.NotNull(response.AccessToken);
        }

        [Fact]
        public async Task SerializeAccessTokenAsync_AllowsHandlingSerialization() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnSerializeAccessToken = context => {
                    context.AccessToken = "access_token";
                    context.HandleResponse();

                    return Task.FromResult(0);
                };

                options.Provider.OnValidateTokenRequest = context => {
                    context.Skip();

                    return Task.FromResult(0);
                };

                options.Provider.OnHandleTokenRequest = context => {
                    var identity = new ClaimsIdentity(context.Options.AuthenticationType);
                    identity.AddClaim(ClaimTypes.NameIdentifier, "Bob le Magnifique");

                    context.Validate(identity);

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest {
                GrantType = OpenIdConnectConstants.GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w"
            });

            // Assert
            Assert.Equal("access_token", response.AccessToken);
        }

        [Fact]
        public async Task SerializeAccessTokenAsync_AllowsSkippingSerialization() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnSerializeAccessToken = context => {
                    context.SkipToNextMiddleware();

                    return Task.FromResult(0);
                };

                options.Provider.OnValidateTokenRequest = context => {
                    context.Skip();

                    return Task.FromResult(0);
                };

                options.Provider.OnHandleTokenRequest = context => {
                    var identity = new ClaimsIdentity(context.Options.AuthenticationType);
                    identity.AddClaim(ClaimTypes.NameIdentifier, "Bob le Magnifique");

                    context.Validate(identity);

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest {
                GrantType = OpenIdConnectConstants.GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w"
            });

            // Assert
            Assert.Null(response.AccessToken);
        }

        [Fact]
        public async Task SerializeAccessTokenAsync_UsesAccessTokenFormatByDefault() {
            // Arrange
            var format = new Mock<ISecureDataFormat<AuthenticationTicket>>();
            format.Setup(mock => mock.Protect(It.IsAny<AuthenticationTicket>()))
                .Returns("7F82F1A3-8C9F-489F-B838-4B644B7C92B2")
                .Verifiable();

            var server = CreateAuthorizationServer(options => {
                options.AccessTokenFormat = format.Object;

                options.Provider.OnValidateTokenRequest = context => {
                    context.Skip();

                    return Task.FromResult(0);
                };

                options.Provider.OnHandleTokenRequest = context => {
                    var identity = new ClaimsIdentity(context.Options.AuthenticationType);
                    identity.AddClaim(ClaimTypes.NameIdentifier, "Bob le Magnifique");

                    context.Validate(identity);

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest {
                GrantType = OpenIdConnectConstants.GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w"
            });

            // Assert
            Assert.Equal("7F82F1A3-8C9F-489F-B838-4B644B7C92B2", response.AccessToken);
            format.Verify(mock => mock.Protect(It.IsAny<AuthenticationTicket>()), Times.Once());
        }

        [Fact]
        public async Task SerializeAccessTokenAsync_MissingSigningCredentialsCauseAnException() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                var handler = new Mock<JwtSecurityTokenHandler>();

                options.AccessTokenHandler = handler.Object;

                options.Provider.OnSerializeAccessToken = context => {
                    context.SigningCredentials = null;

                    return Task.FromResult(0);
                };

                options.Provider.OnValidateTokenRequest = context => {
                    context.Skip();

                    return Task.FromResult(0);
                };

                options.Provider.OnHandleTokenRequest = context => {
                    var identity = new ClaimsIdentity(context.Options.AuthenticationType);
                    identity.AddClaim(ClaimTypes.NameIdentifier, "Bob le Magnifique");

                    context.Validate(identity);

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act and assert
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate {
                return client.PostAsync(TokenEndpoint, new OpenIdConnectRequest {
                    GrantType = OpenIdConnectConstants.GrantTypes.Password,
                    Username = "johndoe",
                    Password = "A3ddj3w"
                });
            });

            Assert.Equal("A signing key must be provided.", exception.Message);
        }

        [Fact]
        public async Task SerializeAccessTokenAsync_UsesAccessTokenHandlerWhenRegistered() {
            // Arrange
            var token = Mock.Of<SecurityToken>();

            var format = new Mock<JwtSecurityTokenHandler>();

            format.Setup(mock => mock.CreateToken(It.IsAny<SecurityTokenDescriptor>()))
                .Returns(token)
                .Verifiable();

            format.Setup(mock => mock.WriteToken(token))
                .Returns("7F82F1A3-8C9F-489F-B838-4B644B7C92B2")
                .Verifiable();

            var server = CreateAuthorizationServer(options => {
                options.AccessTokenHandler = format.Object;

                options.Provider.OnValidateTokenRequest = context => {
                    context.Skip();

                    return Task.FromResult(0);
                };

                options.Provider.OnHandleTokenRequest = context => {
                    var identity = new ClaimsIdentity(context.Options.AuthenticationType);
                    identity.AddClaim(ClaimTypes.NameIdentifier, "Bob le Magnifique");

                    context.Validate(identity);

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest {
                GrantType = OpenIdConnectConstants.GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w"
            });

            // Assert
            Assert.Equal("7F82F1A3-8C9F-489F-B838-4B644B7C92B2", response.AccessToken);
            format.Verify(mock => mock.CreateToken(It.IsAny<SecurityTokenDescriptor>()), Times.Once());
            format.Verify(mock => mock.WriteToken(token), Times.Once());
        }

        [Fact]
        public async Task SerializeIdentityTokenAsync_ExpirationDateIsInferredFromCurrentDatetime() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnSerializeIdentityToken = context => {
                    // Assert
                    Assert.NotNull(context.Ticket.Properties.IssuedUtc);
                    Assert.NotNull(context.Ticket.Properties.ExpiresUtc);

                    Assert.Equal(context.Ticket.Properties.IssuedUtc +
                                 context.Options.IdentityTokenLifetime,
                        context.Ticket.Properties.ExpiresUtc);

                    return Task.FromResult(0);
                };

                options.Provider.OnValidateTokenRequest = context => {
                    context.Skip();

                    return Task.FromResult(0);
                };

                options.Provider.OnHandleTokenRequest = context => {
                    var identity = new ClaimsIdentity(context.Options.AuthenticationType);
                    identity.AddClaim(ClaimTypes.NameIdentifier, "Bob le Magnifique");

                    context.Validate(identity);

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

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
        public async Task SerializeIdentityTokenAsync_ClaimsWithoutAppropriateDestinationAreIgnored() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnSerializeIdentityToken = context => {
                    // Assert
                    Assert.Null(context.Ticket.Identity.GetClaim(ClaimTypes.GivenName));

                    return Task.FromResult(0);
                };

                options.Provider.OnValidateTokenRequest = context => {
                    context.Skip();

                    return Task.FromResult(0);
                };

                options.Provider.OnHandleTokenRequest = context => {
                    var identity = new ClaimsIdentity(context.Options.AuthenticationType);
                    identity.AddClaim(ClaimTypes.NameIdentifier, "Bob le Magnifique");
                    identity.AddClaim(ClaimTypes.GivenName, "Bob");

                    context.Validate(identity);

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

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
        public async Task SerializeIdentityTokenAsync_ClaimsWithAppropriateDestinationAreIncluded() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnSerializeIdentityToken = context => {
                    // Assert
                    Assert.Equal("Bob", context.Ticket.Identity.GetClaim(ClaimTypes.GivenName));

                    return Task.FromResult(0);
                };

                options.Provider.OnValidateTokenRequest = context => {
                    context.Skip();

                    return Task.FromResult(0);
                };

                options.Provider.OnHandleTokenRequest = context => {
                    var identity = new ClaimsIdentity(context.Options.AuthenticationType);
                    identity.AddClaim(ClaimTypes.NameIdentifier, "Bob le Magnifique");
                    identity.AddClaim(ClaimTypes.GivenName, "Bob", OpenIdConnectConstants.Destinations.IdentityToken);

                    context.Validate(identity);

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

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
        public async Task SerializeIdentityTokenAsync_BasicPropertiesAreAutomaticallyAdded() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnSerializeIdentityToken = context => {
                    // Assert
                    Assert.Equal(OpenIdConnectConstants.Usages.IdentityToken, context.Ticket.GetUsage());
                    Assert.Equal("Fabrikam", context.Ticket.GetProperty(OpenIdConnectConstants.Properties.Presenters));
                    Assert.NotNull(context.Ticket.GetTicketId());

                    return Task.FromResult(0);
                };

                options.Provider.OnValidateTokenRequest = context => {
                    context.Skip();

                    return Task.FromResult(0);
                };

                options.Provider.OnHandleTokenRequest = context => {
                    var identity = new ClaimsIdentity(context.Options.AuthenticationType);
                    identity.AddClaim(ClaimTypes.NameIdentifier, "Bob le Magnifique");

                    context.Validate(identity);

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest {
                ClientId = "Fabrikam",
                GrantType = OpenIdConnectConstants.GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w",
                Scope = OpenIdConnectConstants.Scopes.OpenId
            });

            // Assert
            Assert.NotNull(response.IdToken);
        }

        [Fact]
        public async Task SerializeIdentityTokenAsync_AllowsHandlingSerialization() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnSerializeIdentityToken = context => {
                    context.IdentityToken = "identity_token";
                    context.HandleResponse();

                    return Task.FromResult(0);
                };

                options.Provider.OnValidateTokenRequest = context => {
                    context.Skip();

                    return Task.FromResult(0);
                };

                options.Provider.OnHandleTokenRequest = context => {
                    var identity = new ClaimsIdentity(context.Options.AuthenticationType);
                    identity.AddClaim(ClaimTypes.NameIdentifier, "Bob le Magnifique");

                    context.Validate(identity);

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest {
                GrantType = OpenIdConnectConstants.GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w",
                Scope = OpenIdConnectConstants.Scopes.OpenId
            });

            // Assert
            Assert.Equal("identity_token", response.IdToken);
        }

        [Fact]
        public async Task SerializeIdentityTokenAsync_AllowsSkippingSerialization() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnSerializeIdentityToken = context => {
                    context.SkipToNextMiddleware();

                    return Task.FromResult(0);
                };

                options.Provider.OnValidateTokenRequest = context => {
                    context.Skip();

                    return Task.FromResult(0);
                };

                options.Provider.OnHandleTokenRequest = context => {
                    var identity = new ClaimsIdentity(context.Options.AuthenticationType);
                    identity.AddClaim(ClaimTypes.NameIdentifier, "Bob le Magnifique");

                    context.Validate(identity);

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest {
                GrantType = OpenIdConnectConstants.GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w",
                Scope = OpenIdConnectConstants.Scopes.OpenId
            });

            // Assert
            Assert.Null(response.IdToken);
        }

        [Fact]
        public async Task SerializeIdentityTokenAsync_MissingSigningCredentialsCauseAnException() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.IdentityTokenHandler = Mock.Of<JwtSecurityTokenHandler>();

                options.Provider.OnSerializeIdentityToken = context => {
                    context.SigningCredentials = null;

                    return Task.FromResult(0);
                };

                options.Provider.OnValidateTokenRequest = context => {
                    context.Skip();

                    return Task.FromResult(0);
                };

                options.Provider.OnHandleTokenRequest = context => {
                    var identity = new ClaimsIdentity(context.Options.AuthenticationType);
                    identity.AddClaim(ClaimTypes.NameIdentifier, "Bob le Magnifique");

                    context.Validate(identity);

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act and assert
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate {
                return client.PostAsync(TokenEndpoint, new OpenIdConnectRequest {
                    GrantType = OpenIdConnectConstants.GrantTypes.Password,
                    Username = "johndoe",
                    Password = "A3ddj3w",
                    Scope = OpenIdConnectConstants.Scopes.OpenId
                });
            });

            Assert.Equal("A signing key must be provided.", exception.Message);
        }

        [Fact]
        public async Task SerializeIdentityTokenAsync_UsesIdentityTokenHandler() {
            // Arrange
            var format = new Mock<JwtSecurityTokenHandler>();
            format.Setup(mock => mock.CreateToken(It.IsAny<SecurityTokenDescriptor>()))
                .Returns(It.IsAny<SecurityToken>())
                .Verifiable();

            format.Setup(mock => mock.WriteToken(It.IsAny<SecurityToken>()))
                .Returns("7F82F1A3-8C9F-489F-B838-4B644B7C92B2")
                .Verifiable();

            var server = CreateAuthorizationServer(options => {
                options.IdentityTokenHandler = format.Object;

                options.Provider.OnValidateTokenRequest = context => {
                    context.Skip();

                    return Task.FromResult(0);
                };

                options.Provider.OnHandleTokenRequest = context => {
                    var identity = new ClaimsIdentity(context.Options.AuthenticationType);
                    identity.AddClaim(ClaimTypes.NameIdentifier, "Bob le Magnifique");

                    context.Validate(identity);

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest {
                GrantType = OpenIdConnectConstants.GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w",
                Scope = OpenIdConnectConstants.Scopes.OpenId
            });

            // Assert
            Assert.Equal("7F82F1A3-8C9F-489F-B838-4B644B7C92B2", response.IdToken);
            format.Verify(mock => mock.CreateToken(It.IsAny<SecurityTokenDescriptor>()), Times.Once());
            format.Verify(mock => mock.WriteToken(It.IsAny<SecurityToken>()), Times.Once());
        }

        [Fact]
        public async Task SerializeRefreshTokenAsync_ExpirationDateIsInferredFromCurrentDatetime() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnSerializeRefreshToken = context => {
                    // Assert
                    Assert.NotNull(context.Ticket.Properties.IssuedUtc);
                    Assert.NotNull(context.Ticket.Properties.ExpiresUtc);

                    Assert.Equal(context.Ticket.Properties.IssuedUtc +
                                 context.Options.RefreshTokenLifetime,
                        context.Ticket.Properties.ExpiresUtc);

                    return Task.FromResult(0);
                };

                options.Provider.OnValidateTokenRequest = context => {
                    context.Skip();

                    return Task.FromResult(0);
                };

                options.Provider.OnHandleTokenRequest = context => {
                    var identity = new ClaimsIdentity(context.Options.AuthenticationType);
                    identity.AddClaim(ClaimTypes.NameIdentifier, "Bob le Magnifique");

                    var ticket = new AuthenticationTicket(identity, new AuthenticationProperties());
                    ticket.SetScopes(OpenIdConnectConstants.Scopes.OfflineAccess);

                    context.Validate(ticket);

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest {
                GrantType = OpenIdConnectConstants.GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w",
                Scope = OpenIdConnectConstants.Scopes.OfflineAccess
            });

            // Assert
            Assert.NotNull(response.RefreshToken);
        }

        [Fact]
        public async Task SerializeRefreshTokenAsync_BasicPropertiesAreAutomaticallyAdded() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnSerializeRefreshToken = context => {
                    // Assert
                    Assert.Equal(OpenIdConnectConstants.Usages.RefreshToken, context.Ticket.GetUsage());
                    Assert.Equal("Fabrikam", context.Ticket.GetProperty(OpenIdConnectConstants.Properties.Presenters));
                    Assert.NotNull(context.Ticket.GetTicketId());

                    return Task.FromResult(0);
                };

                options.Provider.OnValidateTokenRequest = context => {
                    context.Skip();

                    return Task.FromResult(0);
                };

                options.Provider.OnHandleTokenRequest = context => {
                    var identity = new ClaimsIdentity(context.Options.AuthenticationType);
                    identity.AddClaim(ClaimTypes.NameIdentifier, "Bob le Magnifique");

                    var ticket = new AuthenticationTicket(identity, new AuthenticationProperties());
                    ticket.SetScopes(OpenIdConnectConstants.Scopes.OfflineAccess);

                    context.Validate(ticket);

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest {
                ClientId = "Fabrikam",
                GrantType = OpenIdConnectConstants.GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w",
                Scope = OpenIdConnectConstants.Scopes.OfflineAccess
            });

            // Assert
            Assert.NotNull(response.RefreshToken);
        }

        [Fact]
        public async Task SerializeRefreshTokenAsync_AllowsHandlingSerialization() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnSerializeRefreshToken = context => {
                    context.RefreshToken = "refresh_token";
                    context.HandleResponse();

                    return Task.FromResult(0);
                };

                options.Provider.OnValidateTokenRequest = context => {
                    context.Skip();

                    return Task.FromResult(0);
                };

                options.Provider.OnHandleTokenRequest = context => {
                    var identity = new ClaimsIdentity(context.Options.AuthenticationType);
                    identity.AddClaim(ClaimTypes.NameIdentifier, "Bob le Magnifique");

                    var ticket = new AuthenticationTicket(identity, new AuthenticationProperties());
                    ticket.SetScopes(OpenIdConnectConstants.Scopes.OfflineAccess);

                    context.Validate(ticket);

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest {
                GrantType = OpenIdConnectConstants.GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w",
                Scope = OpenIdConnectConstants.Scopes.OfflineAccess
            });

            // Assert
            Assert.Equal("refresh_token", response.RefreshToken);
        }

        [Fact]
        public async Task SerializeRefreshTokenAsync_AllowsSkippingSerialization() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnSerializeRefreshToken = context => {
                    context.SkipToNextMiddleware();

                    return Task.FromResult(0);
                };

                options.Provider.OnValidateTokenRequest = context => {
                    context.Skip();

                    return Task.FromResult(0);
                };

                options.Provider.OnHandleTokenRequest = context => {
                    var identity = new ClaimsIdentity(context.Options.AuthenticationType);
                    identity.AddClaim(ClaimTypes.NameIdentifier, "Bob le Magnifique");

                    var ticket = new AuthenticationTicket(identity, new AuthenticationProperties());
                    ticket.SetScopes(OpenIdConnectConstants.Scopes.OfflineAccess);

                    context.Validate(ticket);

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest {
                GrantType = OpenIdConnectConstants.GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w",
                Scope = OpenIdConnectConstants.Scopes.OfflineAccess
            });

            // Assert
            Assert.Null(response.RefreshToken);
        }

        [Fact]
        public async Task SerializeRefreshTokenAsync_UsesRefreshTokenFormat() {
            // Arrange
            var format = new Mock<ISecureDataFormat<AuthenticationTicket>>();
            format.Setup(mock => mock.Protect(It.IsAny<AuthenticationTicket>()))
                .Returns("7F82F1A3-8C9F-489F-B838-4B644B7C92B2")
                .Verifiable();

            var server = CreateAuthorizationServer(options => {
                options.RefreshTokenFormat = format.Object;

                options.Provider.OnValidateTokenRequest = context => {
                    context.Skip();

                    return Task.FromResult(0);
                };

                options.Provider.OnHandleTokenRequest = context => {
                    var identity = new ClaimsIdentity(context.Options.AuthenticationType);
                    identity.AddClaim(ClaimTypes.NameIdentifier, "Bob le Magnifique");

                    var ticket = new AuthenticationTicket(identity, new AuthenticationProperties());
                    ticket.SetScopes(OpenIdConnectConstants.Scopes.OfflineAccess);

                    context.Validate(ticket);

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest {
                GrantType = OpenIdConnectConstants.GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w",
                Scope = OpenIdConnectConstants.Scopes.OfflineAccess
            });

            // Assert
            Assert.Equal("7F82F1A3-8C9F-489F-B838-4B644B7C92B2", response.RefreshToken);
            format.Verify(mock => mock.Protect(It.IsAny<AuthenticationTicket>()), Times.Once());
        }

        [Fact]
        public async Task DeserializeAuthorizationCodeAsync_AllowsHandlingSerialization() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnDeserializeAuthorizationCode = context => {
                    // Assert
                    Assert.Equal("authorization_code", context.AuthorizationCode);

                    context.Ticket = new AuthenticationTicket(
                        new ClaimsIdentity(context.Options.AuthenticationType),
                        new AuthenticationProperties());

                    context.HandleResponse();

                    return Task.FromResult(0);
                };

                options.Provider.OnValidateIntrospectionRequest = context => {
                    context.Skip();

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(IntrospectionEndpoint, new OpenIdConnectRequest {
                Token = "authorization_code",
                TokenTypeHint = OpenIdConnectConstants.TokenTypeHints.AuthorizationCode
            });

            // Assert
            Assert.True((bool) response[OpenIdConnectConstants.Claims.Active]);
        }

        [Fact]
        public async Task DeserializeAuthorizationCodeAsync_AllowsSkippingSerialization() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnDeserializeAuthorizationCode = context => {
                    // Assert
                    Assert.Equal("authorization_code", context.AuthorizationCode);

                    context.SkipToNextMiddleware();

                    return Task.FromResult(0);
                };

                options.Provider.OnValidateIntrospectionRequest = context => {
                    context.Skip();

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(IntrospectionEndpoint, new OpenIdConnectRequest {
                Token = "authorization_code",
                TokenTypeHint = OpenIdConnectConstants.TokenTypeHints.AuthorizationCode
            });

            // Assert
            Assert.False((bool) response[OpenIdConnectConstants.Claims.Active]);
        }

        [Fact]
        public async Task DeserializeAuthorizationCodeAsync_UsesAuthorizationCodeFormat() {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsIdentity(OpenIdConnectServerDefaults.AuthenticationType),
                new AuthenticationProperties());

            ticket.SetUsage(OpenIdConnectConstants.Usages.AuthorizationCode);

            var format = new Mock<ISecureDataFormat<AuthenticationTicket>>();
            format.Setup(mock => mock.Unprotect("7F82F1A3-8C9F-489F-B838-4B644B7C92B2"))
                .Returns(ticket)
                .Verifiable();

            var server = CreateAuthorizationServer(options => {
                options.AuthorizationCodeFormat = format.Object;

                options.Provider.OnValidateIntrospectionRequest = context => {
                    context.Skip();

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(IntrospectionEndpoint, new OpenIdConnectRequest {
                Token = "7F82F1A3-8C9F-489F-B838-4B644B7C92B2",
                TokenTypeHint = OpenIdConnectConstants.TokenTypeHints.AuthorizationCode
            });

            // Assert
            Assert.True((bool) response[OpenIdConnectConstants.Claims.Active]);
            format.Verify(mock => mock.Unprotect("7F82F1A3-8C9F-489F-B838-4B644B7C92B2"), Times.Once());
        }

        [Fact]
        public async Task DeserializeAccessTokenAsync_AllowsHandlingSerialization() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnDeserializeAccessToken = context => {
                    // Assert
                    Assert.Equal("access_token", context.AccessToken);

                    context.Ticket = new AuthenticationTicket(
                        new ClaimsIdentity(context.Options.AuthenticationType),
                        new AuthenticationProperties());

                    context.HandleResponse();

                    return Task.FromResult(0);
                };

                options.Provider.OnValidateIntrospectionRequest = context => {
                    context.Skip();

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(IntrospectionEndpoint, new OpenIdConnectRequest {
                Token = "access_token",
                TokenTypeHint = OpenIdConnectConstants.TokenTypeHints.AccessToken
            });

            // Assert
            Assert.True((bool) response[OpenIdConnectConstants.Claims.Active]);
        }

        [Fact]
        public async Task DeserializeAccessTokenAsync_AllowsSkippingSerialization() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnDeserializeAccessToken = context => {
                    // Assert
                    Assert.Equal("access_token", context.AccessToken);

                    context.SkipToNextMiddleware();

                    return Task.FromResult(0);
                };

                options.Provider.OnValidateIntrospectionRequest = context => {
                    context.Skip();

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(IntrospectionEndpoint, new OpenIdConnectRequest {
                Token = "access_token",
                TokenTypeHint = OpenIdConnectConstants.TokenTypeHints.AccessToken
            });

            // Assert
            Assert.False((bool) response[OpenIdConnectConstants.Claims.Active]);
        }

        [Fact]
        public async Task DeserializeAccessTokenAsync_UsesAccessTokenFormatByDefault() {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsIdentity(OpenIdConnectServerDefaults.AuthenticationType),
                new AuthenticationProperties());

            ticket.SetUsage(OpenIdConnectConstants.Usages.AccessToken);

            var format = new Mock<ISecureDataFormat<AuthenticationTicket>>();
            format.Setup(mock => mock.Unprotect("7F82F1A3-8C9F-489F-B838-4B644B7C92B2"))
                .Returns(ticket)
                .Verifiable();

            var server = CreateAuthorizationServer(options => {
                options.AccessTokenFormat = format.Object;

                options.Provider.OnValidateIntrospectionRequest = context => {
                    context.Skip();

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(IntrospectionEndpoint, new OpenIdConnectRequest {
                Token = "7F82F1A3-8C9F-489F-B838-4B644B7C92B2",
                TokenTypeHint = OpenIdConnectConstants.TokenTypeHints.AccessToken
            });

            // Assert
            Assert.True((bool) response[OpenIdConnectConstants.Claims.Active]);
            format.Verify(mock => mock.Unprotect("7F82F1A3-8C9F-489F-B838-4B644B7C92B2"), Times.Once());
        }

        [Fact]
        public async Task DeserializeAccessTokenAsync_UsesAccessTokenHandlerWhenRegistered() {
            // Arrange
            var token = Mock.Of<SecurityToken>(mock =>
                mock.ValidFrom == DateTime.UtcNow.AddDays(-1) &&
                mock.ValidTo == DateTime.UtcNow.AddDays(1));

            var identity = new ClaimsIdentity(OpenIdConnectServerDefaults.AuthenticationType);
            identity.AddClaim(OpenIdConnectConstants.Claims.Usage, OpenIdConnectConstants.Usages.AccessToken);

            var format = new Mock<JwtSecurityTokenHandler>();

            format.Setup(mock => mock.CanReadToken("7F82F1A3-8C9F-489F-B838-4B644B7C92B2"))
                .Returns(true)
                .Verifiable();

            format.Setup(mock => mock.ValidateToken(
                "7F82F1A3-8C9F-489F-B838-4B644B7C92B2",
                It.IsAny<TokenValidationParameters>(), out token))
                .Returns(new ClaimsPrincipal(identity))
                .Verifiable();

            var server = CreateAuthorizationServer(options => {
                options.AccessTokenHandler = format.Object;

                options.Provider.OnValidateIntrospectionRequest = context => {
                    context.Skip();

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(IntrospectionEndpoint, new OpenIdConnectRequest {
                Token = "7F82F1A3-8C9F-489F-B838-4B644B7C92B2",
                TokenTypeHint = OpenIdConnectConstants.TokenTypeHints.AccessToken
            });

            // Assert
            Assert.True((bool) response[OpenIdConnectConstants.Claims.Active]);

            format.Verify(mock => mock.CanReadToken("7F82F1A3-8C9F-489F-B838-4B644B7C92B2"), Times.Once());

            format.Verify(mock => mock.ValidateToken(
                    "7F82F1A3-8C9F-489F-B838-4B644B7C92B2",
                    It.IsAny<TokenValidationParameters>(), out token), Times.Once());
        }

        [Fact]
        public async Task DeserializeIdentityTokenAsync_AllowsHandlingSerialization() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnDeserializeIdentityToken = context => {
                    // Assert
                    Assert.Equal("id_token", context.IdentityToken);

                    context.Ticket = new AuthenticationTicket(
                        new ClaimsIdentity(context.Options.AuthenticationType),
                        new AuthenticationProperties());

                    context.HandleResponse();

                    return Task.FromResult(0);
                };

                options.Provider.OnValidateIntrospectionRequest = context => {
                    context.Skip();

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(IntrospectionEndpoint, new OpenIdConnectRequest {
                Token = "id_token",
                TokenTypeHint = OpenIdConnectConstants.TokenTypeHints.IdToken
            });

            // Assert
            Assert.True((bool) response[OpenIdConnectConstants.Claims.Active]);
        }

        [Fact]
        public async Task DeserializeIdentityTokenAsync_AllowsSkippingSerialization() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnDeserializeIdentityToken = context => {
                    // Assert
                    Assert.Equal("id_token", context.IdentityToken);

                    context.SkipToNextMiddleware();

                    return Task.FromResult(0);
                };

                options.Provider.OnValidateIntrospectionRequest = context => {
                    context.Skip();

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(IntrospectionEndpoint, new OpenIdConnectRequest {
                Token = "id_token",
                TokenTypeHint = OpenIdConnectConstants.TokenTypeHints.IdToken
            });

            // Assert
            Assert.False((bool) response[OpenIdConnectConstants.Claims.Active]);
        }

        [Fact]
        public async Task DeserializeIdentityTokenAsync_UsesIdentityTokenHandler() {
            // Arrange
            var token = Mock.Of<SecurityToken>(mock =>
                mock.ValidFrom == DateTime.UtcNow.AddDays(-1) &&
                mock.ValidTo == DateTime.UtcNow.AddDays(1));

            var identity = new ClaimsIdentity(OpenIdConnectServerDefaults.AuthenticationType);
            identity.AddClaim(OpenIdConnectConstants.Claims.Usage, OpenIdConnectConstants.Usages.IdentityToken);

            var format = new Mock<JwtSecurityTokenHandler>();

            format.As<ISecurityTokenValidator>()
                .Setup(mock => mock.CanReadToken("7F82F1A3-8C9F-489F-B838-4B644B7C92B2"))
                .Returns(true)
                .Verifiable();

            format.As<ISecurityTokenValidator>()
                .Setup(mock => mock.ValidateToken(
                    "7F82F1A3-8C9F-489F-B838-4B644B7C92B2",
                    It.IsAny<TokenValidationParameters>(), out token))
                .Returns(new ClaimsPrincipal(identity))
                .Verifiable();

            var server = CreateAuthorizationServer(options => {
                options.IdentityTokenHandler = format.Object;

                options.Provider.OnValidateIntrospectionRequest = context => {
                    context.Skip();

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(IntrospectionEndpoint, new OpenIdConnectRequest {
                Token = "7F82F1A3-8C9F-489F-B838-4B644B7C92B2",
                TokenTypeHint = OpenIdConnectConstants.TokenTypeHints.IdToken
            });

            // Assert
            Assert.True((bool) response[OpenIdConnectConstants.Claims.Active]);

            format.As<ISecurityTokenValidator>()
                .Verify(mock => mock.CanReadToken("7F82F1A3-8C9F-489F-B838-4B644B7C92B2"), Times.Once());

            format.As<ISecurityTokenValidator>()
                .Verify(mock => mock.ValidateToken(
                    "7F82F1A3-8C9F-489F-B838-4B644B7C92B2",
                    It.IsAny<TokenValidationParameters>(), out token), Times.Once());
        }

        [Fact]
        public async Task DeserializeRefreshTokenAsync_AllowsHandlingSerialization() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnDeserializeRefreshToken = context => {
                    // Assert
                    Assert.Equal("refresh_token", context.RefreshToken);

                    context.Ticket = new AuthenticationTicket(
                        new ClaimsIdentity(context.Options.AuthenticationType),
                        new AuthenticationProperties());

                    context.HandleResponse();

                    return Task.FromResult(0);
                };

                options.Provider.OnValidateIntrospectionRequest = context => {
                    context.Skip();

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(IntrospectionEndpoint, new OpenIdConnectRequest {
                Token = "refresh_token",
                TokenTypeHint = OpenIdConnectConstants.TokenTypeHints.RefreshToken
            });

            // Assert
            Assert.True((bool) response[OpenIdConnectConstants.Claims.Active]);
        }

        [Fact]
        public async Task DeserializeRefreshTokenAsync_AllowsSkippingSerialization() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnDeserializeRefreshToken = context => {
                    // Assert
                    Assert.Equal("refresh_token", context.RefreshToken);

                    context.SkipToNextMiddleware();

                    return Task.FromResult(0);
                };

                options.Provider.OnValidateIntrospectionRequest = context => {
                    context.Skip();

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(IntrospectionEndpoint, new OpenIdConnectRequest {
                Token = "refresh_token",
                TokenTypeHint = OpenIdConnectConstants.TokenTypeHints.RefreshToken
            });

            // Assert
            Assert.False((bool) response[OpenIdConnectConstants.Claims.Active]);
        }

        [Fact]
        public async Task DeserializeRefreshTokenAsync_UsesRefreshTokenFormat() {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsIdentity(OpenIdConnectServerDefaults.AuthenticationType),
                new AuthenticationProperties());

            ticket.SetUsage(OpenIdConnectConstants.Usages.RefreshToken);

            var format = new Mock<ISecureDataFormat<AuthenticationTicket>>();
            format.Setup(mock => mock.Unprotect("7F82F1A3-8C9F-489F-B838-4B644B7C92B2"))
                .Returns(ticket)
                .Verifiable();

            var server = CreateAuthorizationServer(options => {
                options.RefreshTokenFormat = format.Object;

                options.Provider.OnValidateIntrospectionRequest = context => {
                    context.Skip();

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.PostAsync(IntrospectionEndpoint, new OpenIdConnectRequest {
                Token = "7F82F1A3-8C9F-489F-B838-4B644B7C92B2",
                TokenTypeHint = OpenIdConnectConstants.TokenTypeHints.RefreshToken
            });

            // Assert
            Assert.True((bool) response[OpenIdConnectConstants.Claims.Active]);
            format.Verify(mock => mock.Unprotect("7F82F1A3-8C9F-489F-B838-4B644B7C92B2"), Times.Once());
        }
    }
}
