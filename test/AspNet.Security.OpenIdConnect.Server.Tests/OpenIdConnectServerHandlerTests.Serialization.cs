/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Reflection;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Client;
using AspNet.Security.OpenIdConnect.Extensions;
using AspNet.Security.OpenIdConnect.Primitives;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Moq;
using Xunit;

namespace AspNet.Security.OpenIdConnect.Server.Tests
{
    public partial class OpenIdConnectServerHandlerTests
    {
        [Fact]
        public async Task SerializeAuthorizationCodeAsync_ExpirationDateIsNotAddedWhenLifetimeIsNull()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.AuthorizationCodeLifetime = null;

                options.Provider.OnSerializeAuthorizationCode = context =>
                {
                    // Assert
                    Assert.NotNull(context.Ticket.Properties.IssuedUtc);
                    Assert.Null(context.Ticket.Properties.ExpiresUtc);

                    return Task.CompletedTask;
                };

                options.Provider.OnValidateAuthorizationRequest = context =>
                {
                    context.Validate();

                    return Task.CompletedTask;
                };

                options.Provider.OnHandleAuthorizationRequest = context =>
                {
                    var identity = new ClaimsIdentity(OpenIdConnectServerDefaults.AuthenticationScheme);
                    identity.AddClaim(OpenIdConnectConstants.Claims.Subject, "Bob le Magnifique");

                    context.Validate(new ClaimsPrincipal(identity));

                    return Task.CompletedTask;
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
            Assert.NotNull(response.Code);
        }

        [Fact]
        public async Task SerializeAuthorizationCodeAsync_ExpirationDateIsInferredFromCurrentDatetime()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnSerializeAuthorizationCode = context =>
                {
                    // Assert
                    Assert.NotNull(context.Ticket.Properties.IssuedUtc);
                    Assert.NotNull(context.Ticket.Properties.ExpiresUtc);

                    Assert.Equal(context.Ticket.Properties.IssuedUtc +
                                 context.Options.AuthorizationCodeLifetime,
                        context.Ticket.Properties.ExpiresUtc);

                    return Task.CompletedTask;
                };

                options.Provider.OnValidateAuthorizationRequest = context =>
                {
                    context.Validate();

                    return Task.CompletedTask;
                };

                options.Provider.OnHandleAuthorizationRequest = context =>
                {
                    var identity = new ClaimsIdentity(OpenIdConnectServerDefaults.AuthenticationScheme);
                    identity.AddClaim(OpenIdConnectConstants.Claims.Subject, "Bob le Magnifique");

                    context.Validate(new ClaimsPrincipal(identity));

                    return Task.CompletedTask;
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
            Assert.NotNull(response.Code);
        }

        [Fact]
        public async Task SerializeAuthorizationCodeAsync_ExpirationDateCanBeOverridenFromUserCode()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnSerializeAuthorizationCode = context =>
                {
                    // Assert
                    Assert.NotNull(context.Ticket.Properties.IssuedUtc);
                    Assert.NotNull(context.Ticket.Properties.ExpiresUtc);

                    Assert.Equal(context.Ticket.Properties.IssuedUtc + TimeSpan.FromDays(42),
                                 context.Ticket.Properties.ExpiresUtc);

                    return Task.CompletedTask;
                };

                options.Provider.OnValidateAuthorizationRequest = context =>
                {
                    context.Validate();

                    return Task.CompletedTask;
                };

                options.Provider.OnHandleAuthorizationRequest = context =>
                {
                    var identity = new ClaimsIdentity(OpenIdConnectServerDefaults.AuthenticationScheme);
                    identity.AddClaim(OpenIdConnectConstants.Claims.Subject, "Bob le Magnifique");

                    var ticket = new AuthenticationTicket(
                        new ClaimsPrincipal(identity),
                        new AuthenticationProperties(),
                        OpenIdConnectServerDefaults.AuthenticationScheme);

                    ticket.SetAuthorizationCodeLifetime(TimeSpan.FromDays(42));

                    context.Validate(ticket);

                    return Task.CompletedTask;
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
            Assert.NotNull(response.Code);
        }

        [Fact]
        public async Task SerializeAuthorizationCodeAsync_ParametersAreCopiedToAuthorizationCode()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnSerializeAuthorizationCode = context =>
                {
                    // Assert
                    Assert.Equal("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                        context.Ticket.GetProperty(OpenIdConnectConstants.Properties.CodeChallenge));

                    Assert.Equal(OpenIdConnectConstants.CodeChallengeMethods.Sha256,
                        context.Ticket.GetProperty(OpenIdConnectConstants.Properties.CodeChallengeMethod));

                    Assert.Equal("n-0S6_WzA2Mj", context.Ticket.GetProperty(OpenIdConnectConstants.Properties.Nonce));

                    Assert.Equal("http://www.fabrikam.com/path",
                        context.Ticket.GetProperty(OpenIdConnectConstants.Properties.OriginalRedirectUri));

                    return Task.CompletedTask;
                };

                options.Provider.OnValidateAuthorizationRequest = context =>
                {
                    context.Validate();

                    return Task.CompletedTask;
                };

                options.Provider.OnHandleAuthorizationRequest = context =>
                {
                    var identity = new ClaimsIdentity(OpenIdConnectServerDefaults.AuthenticationScheme);
                    identity.AddClaim(OpenIdConnectConstants.Claims.Subject, "Bob le Magnifique");

                    context.Validate(new ClaimsPrincipal(identity));

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(AuthorizationEndpoint, new OpenIdConnectRequest
            {
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
        public async Task SerializeAuthorizationCodeAsync_BasicPropertiesAreAutomaticallyAdded()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnSerializeAuthorizationCode = context =>
                {
                    // Assert
                    Assert.Equal(new[] { "Fabrikam" }, context.Ticket.GetPresenters());
                    Assert.NotNull(context.Ticket.GetTokenId());

                    return Task.CompletedTask;
                };

                options.Provider.OnValidateAuthorizationRequest = context =>
                {
                    context.Validate();

                    return Task.CompletedTask;
                };

                options.Provider.OnHandleAuthorizationRequest = context =>
                {
                    var identity = new ClaimsIdentity(OpenIdConnectServerDefaults.AuthenticationScheme);
                    identity.AddClaim(OpenIdConnectConstants.Claims.Subject, "Bob le Magnifique");

                    context.Validate(new ClaimsPrincipal(identity));

                    return Task.CompletedTask;
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
            Assert.NotNull(response.Code);
        }

        [Fact]
        public async Task SerializeAuthorizationCodeAsync_RemovesUnnecessaryProperties()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnSerializeAuthorizationCode = context =>
                {
                    // Assert
                    Assert.Null(context.Ticket.GetProperty(OpenIdConnectConstants.Properties.AuthorizationCodeLifetime));
                    Assert.Null(context.Ticket.GetProperty(OpenIdConnectConstants.Properties.TokenUsage));

                    return Task.CompletedTask;
                };

                options.Provider.OnValidateAuthorizationRequest = context =>
                {
                    context.Validate();

                    return Task.CompletedTask;
                };

                options.Provider.OnHandleAuthorizationRequest = context =>
                {
                    var identity = new ClaimsIdentity(OpenIdConnectServerDefaults.AuthenticationScheme);
                    identity.AddClaim(OpenIdConnectConstants.Claims.Subject, "Bob le Magnifique");

                    context.Validate(new ClaimsPrincipal(identity));

                    return Task.CompletedTask;
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
            Assert.NotNull(response.Code);
        }

        [Fact]
        public async Task SerializeAuthorizationCodeAsync_AllowsHandlingSerialization()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnSerializeAuthorizationCode = context =>
                {
                    context.AuthorizationCode = "authorization_code";
                    context.HandleSerialization();

                    return Task.CompletedTask;
                };

                options.Provider.OnValidateAuthorizationRequest = context =>
                {
                    context.Validate();

                    return Task.CompletedTask;
                };

                options.Provider.OnHandleAuthorizationRequest = context =>
                {
                    var identity = new ClaimsIdentity(OpenIdConnectServerDefaults.AuthenticationScheme);
                    identity.AddClaim(OpenIdConnectConstants.Claims.Subject, "Bob le Magnifique");

                    context.Validate(new ClaimsPrincipal(identity));

                    return Task.CompletedTask;
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
            Assert.Equal("authorization_code", response.Code);
        }

        [Fact]
        public async Task SerializeAuthorizationCodeAsync_ThrowsAnExceptionForNullDataFormat()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnSerializeAuthorizationCode = context =>
                {
                    context.DataFormat = null;

                    return Task.CompletedTask;
                };

                options.Provider.OnValidateAuthorizationRequest = context =>
                {
                    context.Validate();

                    return Task.CompletedTask;
                };

                options.Provider.OnHandleAuthorizationRequest = context =>
                {
                    var identity = new ClaimsIdentity(OpenIdConnectServerDefaults.AuthenticationScheme);
                    identity.AddClaim(OpenIdConnectConstants.Claims.Subject, "Bob le Magnifique");

                    context.Validate(new ClaimsPrincipal(identity));

                    return Task.CompletedTask;
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
                    ResponseType = OpenIdConnectConstants.ResponseTypes.Code,
                    Scope = OpenIdConnectConstants.Scopes.OpenId
                });
            });

            Assert.Equal("A data formatter must be provided.", exception.Message);
        }

        [Fact]
        public async Task SerializeAuthorizationCodeAsync_UsesAuthorizationCodeFormat()
        {
            // Arrange
            var format = new Mock<ISecureDataFormat<AuthenticationTicket>>();
            format.Setup(mock => mock.Protect(It.IsAny<AuthenticationTicket>()))
                .Returns("7F82F1A3-8C9F-489F-B838-4B644B7C92B2")
                .Verifiable();

            var server = CreateAuthorizationServer(options =>
            {
                options.AuthorizationCodeFormat = format.Object;

                options.Provider.OnValidateAuthorizationRequest = context =>
                {
                    context.Validate();

                    return Task.CompletedTask;
                };

                options.Provider.OnHandleAuthorizationRequest = context =>
                {
                    var identity = new ClaimsIdentity(OpenIdConnectServerDefaults.AuthenticationScheme);
                    identity.AddClaim(OpenIdConnectConstants.Claims.Subject, "Bob le Magnifique");

                    context.Validate(new ClaimsPrincipal(identity));

                    return Task.CompletedTask;
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
            Assert.Equal("7F82F1A3-8C9F-489F-B838-4B644B7C92B2", response.Code);
            format.Verify(mock => mock.Protect(It.IsAny<AuthenticationTicket>()), Times.Once());
        }

        [Fact]
        public async Task SerializeAccessTokenAsync_ExpirationDateIsNotAddedWhenLifetimeIsNull()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.AccessTokenLifetime = null;

                options.Provider.OnSerializeAccessToken = context =>
                {
                    // Assert
                    Assert.NotNull(context.Ticket.Properties.IssuedUtc);
                    Assert.Null(context.Ticket.Properties.ExpiresUtc);

                    return Task.CompletedTask;
                };

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
            Assert.NotNull(response.AccessToken);
        }

        [Fact]
        public async Task SerializeAccessTokenAsync_ExpirationDateIsInferredFromCurrentDatetime()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnSerializeAccessToken = context =>
                {
                    // Assert
                    Assert.NotNull(context.Ticket.Properties.IssuedUtc);
                    Assert.NotNull(context.Ticket.Properties.ExpiresUtc);

                    Assert.Equal(context.Ticket.Properties.IssuedUtc +
                                 context.Options.AccessTokenLifetime,
                        context.Ticket.Properties.ExpiresUtc);

                    return Task.CompletedTask;
                };

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
            Assert.NotNull(response.AccessToken);
        }

        [Fact]
        public async Task SerializeAccessTokenAsync_ExpirationDateCanBeOverridenFromUserCode()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnSerializeAccessToken = context =>
                {
                    // Assert
                    Assert.NotNull(context.Ticket.Properties.IssuedUtc);
                    Assert.NotNull(context.Ticket.Properties.ExpiresUtc);

                    Assert.Equal(context.Ticket.Properties.IssuedUtc + TimeSpan.FromDays(42),
                                 context.Ticket.Properties.ExpiresUtc);

                    return Task.CompletedTask;
                };

                options.Provider.OnValidateTokenRequest = context =>
                {
                    context.Skip();

                    return Task.CompletedTask;
                };

                options.Provider.OnHandleTokenRequest = context =>
                {
                    var identity = new ClaimsIdentity(OpenIdConnectServerDefaults.AuthenticationScheme);
                    identity.AddClaim(OpenIdConnectConstants.Claims.Subject, "Bob le Magnifique");

                    var ticket = new AuthenticationTicket(
                        new ClaimsPrincipal(identity),
                        new AuthenticationProperties(),
                        OpenIdConnectServerDefaults.AuthenticationScheme);

                    ticket.SetAccessTokenLifetime(TimeSpan.FromDays(42));

                    context.Validate(ticket);

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
            Assert.NotNull(response.AccessToken);
        }

        [Fact]
        public async Task SerializeAccessTokenAsync_ClaimsWithoutAppropriateDestinationAreIgnored()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnSerializeAccessToken = context =>
                {
                    // Assert
                    Assert.Null(context.Ticket.Principal.GetClaim(OpenIdConnectConstants.Claims.GivenName));

                    return Task.CompletedTask;
                };

                options.Provider.OnValidateTokenRequest = context =>
                {
                    context.Skip();

                    return Task.CompletedTask;
                };

                options.Provider.OnHandleTokenRequest = context =>
                {
                    var identity = new ClaimsIdentity(OpenIdConnectServerDefaults.AuthenticationScheme);
                    identity.AddClaim(OpenIdConnectConstants.Claims.Subject, "Bob le Magnifique");
                    identity.AddClaim(OpenIdConnectConstants.Claims.GivenName, "Bob");

                    context.Validate(new ClaimsPrincipal(identity));

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
            Assert.NotNull(response.AccessToken);
        }

        [Fact]
        public async Task SerializeAccessTokenAsync_ClaimsWithAppropriateDestinationAreIncluded()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnSerializeAccessToken = context =>
                {
                    // Assert
                    Assert.Equal("Bob", context.Ticket.Principal.GetClaim(OpenIdConnectConstants.Claims.GivenName));

                    return Task.CompletedTask;
                };

                options.Provider.OnValidateTokenRequest = context =>
                {
                    context.Skip();

                    return Task.CompletedTask;
                };

                options.Provider.OnHandleTokenRequest = context =>
                {
                    var identity = new ClaimsIdentity(OpenIdConnectServerDefaults.AuthenticationScheme);
                    identity.AddClaim(OpenIdConnectConstants.Claims.Subject, "Bob le Magnifique");
                    identity.AddClaim(OpenIdConnectConstants.Claims.GivenName, "Bob", OpenIdConnectConstants.Destinations.AccessToken);

                    context.Validate(new ClaimsPrincipal(identity));

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
            Assert.NotNull(response.AccessToken);
        }

        [Fact]
        public async Task SerializeAccessTokenAsync_BasicPropertiesAreAutomaticallyAdded()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnSerializeAccessToken = context =>
                {
                    // Assert
                    Assert.Equal(new[] { "Fabrikam" }, context.Ticket.GetPresenters());
                    Assert.NotNull(context.Ticket.GetTokenId());

                    return Task.CompletedTask;
                };

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
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                GrantType = OpenIdConnectConstants.GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w"
            });

            // Assert
            Assert.NotNull(response.AccessToken);
        }

        [Fact]
        public async Task SerializeAccessTokenAsync_RemovesUnnecessaryProperties()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnSerializeAccessToken = context =>
                {
                    // Assert
                    Assert.Null(context.Ticket.GetProperty(OpenIdConnectConstants.Properties.AccessTokenLifetime));
                    Assert.Null(context.Ticket.GetProperty(OpenIdConnectConstants.Properties.AuthorizationCodeLifetime));
                    Assert.Null(context.Ticket.GetProperty(OpenIdConnectConstants.Properties.CodeChallenge));
                    Assert.Null(context.Ticket.GetProperty(OpenIdConnectConstants.Properties.CodeChallengeMethod));
                    Assert.Null(context.Ticket.GetProperty(OpenIdConnectConstants.Properties.IdentityTokenLifetime));
                    Assert.Null(context.Ticket.GetProperty(OpenIdConnectConstants.Properties.Nonce));
                    Assert.Null(context.Ticket.GetProperty(OpenIdConnectConstants.Properties.OriginalRedirectUri));
                    Assert.Null(context.Ticket.GetProperty(OpenIdConnectConstants.Properties.RefreshTokenLifetime));
                    Assert.Null(context.Ticket.GetProperty(OpenIdConnectConstants.Properties.TokenUsage));

                    return Task.CompletedTask;
                };

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
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                GrantType = OpenIdConnectConstants.GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w"
            });

            // Assert
            Assert.NotNull(response.AccessToken);
        }

        [Fact]
        public async Task SerializeAccessTokenAsync_IgnoresAsymmetricEncryptingKeys()
        {
            // Arrange
            var parameters = new RSAParameters
            {
                D = Convert.FromBase64String("Uj6NrYBnyddhlJefYEP2nleCntAKlWyIttJC4cJnNxNN+OT2fQXhpTXRwW4R5YIS3HDqK/Fg2yoYm+OTVntAAgRFKveRx/WKwFo6UpnJc5u3lElhFa7IfosO9qXjErpX9ruAVqipekDLwQ++KmVVdgH4PK/o//nEx5zklGCdlEJURZYJPs9/7g1cx3UwvPp8jM7LgZL5OZRNyI3Jz4efrwiI2/vd8P28lAbpv/Ao4NwUDq/WKEnZ8JYSjLEKnZCfbX1ZEwf0Ic48jEKHmi1WEwpru1fMPoYfakrsY/VEfatPiDs8a5HABP/KaXcM4AZsr7HbzqAaNycV2xgdZimGcQ=="),
                DP = Convert.FromBase64String("hi1e+0eQ/iYrfT4zpZVbx3dyfA7Ch/aujMt6nGMF+1LGaut86vDHM2JI0Gc2BKc+uPEu2bNAorhSmuSyGpfGYl0MYFQoVF/jyiGpzYPmhYpL5yLuN9jWAqNwjfstuRDLU9zTEfZnr3OSN85rZcgT7NUxlY8im1Y2TWYxGiEXw9E="),
                DQ = Convert.FromBase64String("laVNkWIbnSuGo7nAxyUSdL2sXU3GZWwItwzTG0IK/0woFjArtCxGgNXW+V+GhxT7iHGAVJJSBvJ65TXrUYuBmoWj2CsoUs2mzK8ax4zg3CXrU61esCsGUoS2owR4FXlhYPmoVnglGu89bH72eXKixZsuF7vKW19nG703BXYEaEU="),
                Exponent = Convert.FromBase64String("AQAB"),
                InverseQ = Convert.FromBase64String("dhzLDS4F5WYHX+vH4+uL3Ei/K5lxw2A/dBHGtbS2X54gm7vARl+FrptOFFwIjjmsLuTjttAq9K1EP/XZIq8bjW6dXJ/IytnobIPSFkclEeQlMi4/2VDMG5915J0DwnKO9M+B8F3JViUyMv0pvb+ub+HHDVFkIr7zooCmY25i77Q="),
                Modulus = Convert.FromBase64String("kXv7Pxf6mSf7mu6mPAOAoKAXl5kU7Q3h9zevC5i4Mm5bMk17XCh7ZvVxDzGA+1JmyxOX6sw3gMUl31FtIFlDhis8VnXKAPn8i1zrmebq+7QKzpE2GpoIpXjXbkPaHG/DbC67M1bux7/dE7lSUSifHRRLsbMUC2D4UahJ6miH2iPFNFyoa6CLtwosD8tIJKwmZ9r9zfqc9BrVGu24lZySjTSRttpLaTkgkBjxHmYhinKNEtj9wUfi1S1wPJUvf+roc6o+7jeBBV3EXJCsb6XCCXI7/e3umWp19odeRShXLQNQbNuuVC7yre4iidUDrWJ1jiaB06svUG+fVEi4FCMvEQ=="),
                P = Convert.FromBase64String("xQGczmp4qD7Sez/ZqgW+O4cciTHvSqJqJUSdDd2l1Pd/szQ8avvzorrbSWOIULyv6eJb32+HuyLgy6rTSJ6THFobAnUv4ZTR7EGK26AJmP/BhD+3G+n21+4fzfbAxpHihkCYmO8aEl8fm/r4qPVXmCzFoXDZLMNIxFsdEXiFRS0="),
                Q = Convert.FromBase64String("vQy5C++AzF+TRh6qwbKzOqt87ZHEHidIAh6ivRNewjzIgCWXpseVl7DimY1YdViOnw1VI7xY+EyiyTanq5caTqqB3KcDm2t40bJfrZuUcn/5puRIh1bKNDwIMLsuNCrjHmDlNbocqpYMOh0Pgw7ARNbqrnPjWsYGJPuMNFpax/U=")
            };

            var credentials = new EncryptingCredentials(
                new RsaSecurityKey(parameters),
                SecurityAlgorithms.RsaOAEP,
                SecurityAlgorithms.Aes256CbcHmacSha512);

            var server = CreateAuthorizationServer(options =>
            {
                options.EncryptingCredentials.Insert(0, credentials);
                options.EncryptingCredentials.AddKey(new SymmetricSecurityKey(new byte[256 / 8]));

                options.Provider.OnSerializeAccessToken = context =>
                {
                    // Assert
                    Assert.NotSame(credentials, context.EncryptingCredentials);
                    Assert.Same(context.Options.EncryptingCredentials[1], context.EncryptingCredentials);
                    Assert.IsType<SymmetricSecurityKey>(context.EncryptingCredentials.Key);

                    return Task.CompletedTask;
                };

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
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                GrantType = OpenIdConnectConstants.GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w"
            });

            // Assert
            Assert.NotNull(response.AccessToken);
        }

        [Fact]
        public async Task SerializeAccessTokenAsync_UsesSymmetricEncryptingKey()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.EncryptingCredentials.AddKey(new SymmetricSecurityKey(new byte[256 / 8]));

                options.Provider.OnSerializeAccessToken = context =>
                {
                    // Assert
                    Assert.Same(context.Options.EncryptingCredentials[0], context.EncryptingCredentials);
                    Assert.IsType<SymmetricSecurityKey>(context.EncryptingCredentials.Key);

                    return Task.CompletedTask;
                };

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
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                GrantType = OpenIdConnectConstants.GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w"
            });

            // Assert
            Assert.NotNull(response.AccessToken);
        }

        [Fact]
        public async Task SerializeAccessTokenAsync_PrefersSymmetricSigningKeyWhenAvailable()
        {
            // Arrange
            var credentials = new SigningCredentials(
                new SymmetricSecurityKey(new byte[256 / 8]),
                SecurityAlgorithms.HmacSha256);

            var server = CreateAuthorizationServer(options =>
            {
                options.SigningCredentials.Add(credentials);

                options.Provider.OnSerializeAccessToken = context =>
                {
                    // Assert
                    Assert.Same(credentials, context.SigningCredentials);
                    Assert.IsType<SymmetricSecurityKey>(context.SigningCredentials.Key);

                    return Task.CompletedTask;
                };

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
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                GrantType = OpenIdConnectConstants.GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w"
            });

            // Assert
            Assert.NotNull(response.AccessToken);
        }

        [Fact]
        public async Task SerializeAccessTokenAsync_UsesAsymmetricSigningKey()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnSerializeAccessToken = context =>
                {
                    // Assert
                    Assert.Same(context.Options.SigningCredentials[0], context.SigningCredentials);
                    Assert.IsType<X509SecurityKey>(context.SigningCredentials.Key);

                    return Task.CompletedTask;
                };

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
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                GrantType = OpenIdConnectConstants.GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w"
            });

            // Assert
            Assert.NotNull(response.AccessToken);
        }

        [Fact]
        public async Task SerializeAccessTokenAsync_AllowsHandlingSerialization()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnSerializeAccessToken = context =>
                {
                    context.AccessToken = "access_token";
                    context.HandleSerialization();

                    return Task.CompletedTask;
                };

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
            Assert.Equal("access_token", response.AccessToken);
        }

        [Fact]
        public async Task SerializeAccessTokenAsync_ThrowsAnExceptionForNullDataFormat()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnSerializeAccessToken = context =>
                {
                    context.SecurityTokenHandler = null;
                    context.DataFormat = null;

                    return Task.CompletedTask;
                };

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
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act and assert
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
            {
                return client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
                {
                    GrantType = OpenIdConnectConstants.GrantTypes.Password,
                    Username = "johndoe",
                    Password = "A3ddj3w"
                });
            });

            Assert.Equal("A security token handler or data formatter must be provided.", exception.Message);
        }

        [Fact]
        public async Task SerializeAccessTokenAsync_UsesAccessTokenFormatByDefault()
        {
            // Arrange
            var format = new Mock<ISecureDataFormat<AuthenticationTicket>>();
            format.Setup(mock => mock.Protect(It.IsAny<AuthenticationTicket>()))
                .Returns("7F82F1A3-8C9F-489F-B838-4B644B7C92B2")
                .Verifiable();

            var server = CreateAuthorizationServer(options =>
            {
                options.AccessTokenFormat = format.Object;

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
            Assert.Equal("7F82F1A3-8C9F-489F-B838-4B644B7C92B2", response.AccessToken);
            format.Verify(mock => mock.Protect(It.IsAny<AuthenticationTicket>()), Times.Once());
        }

        [Fact]
        public async Task SerializeAccessTokenAsync_MissingSigningCredentialsCauseAnException()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.AccessTokenHandler = Mock.Of<JwtSecurityTokenHandler>();

                options.Provider.OnSerializeAccessToken = context =>
                {
                    context.SigningCredentials = null;

                    return Task.CompletedTask;
                };

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
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act and assert
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
            {
                return client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
                {
                    GrantType = OpenIdConnectConstants.GrantTypes.Password,
                    Username = "johndoe",
                    Password = "A3ddj3w"
                });
            });

            Assert.Equal("A signing key must be provided.", exception.Message);
        }

        [Fact]
        public async Task SerializeAccessTokenAsync_UsesAccessTokenHandlerWhenRegistered()
        {
            // Arrange
            var format = new Mock<JwtSecurityTokenHandler>();
            format.Setup(mock => mock.CreateEncodedJwt(It.IsAny<SecurityTokenDescriptor>()))
                .Returns("7F82F1A3-8C9F-489F-B838-4B644B7C92B2")
                .Verifiable();

            var server = CreateAuthorizationServer(options =>
            {
                options.AccessTokenHandler = format.Object;

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
            Assert.Equal("7F82F1A3-8C9F-489F-B838-4B644B7C92B2", response.AccessToken);
            format.Verify(mock => mock.CreateEncodedJwt(It.IsAny<SecurityTokenDescriptor>()), Times.Once());
        }

        [Fact]
        public async Task SerializeIdentityTokenAsync_ExpirationDateIsNotAddedWhenLifetimeIsNull()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.IdentityTokenLifetime = null;

                options.Provider.OnSerializeIdentityToken = context =>
                {
                    // Assert
                    Assert.NotNull(context.Ticket.Properties.IssuedUtc);
                    Assert.Null(context.Ticket.Properties.ExpiresUtc);

                    return Task.CompletedTask;
                };

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
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                GrantType = OpenIdConnectConstants.GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w",
                Scope = OpenIdConnectConstants.Scopes.OpenId
            });

            // Assert
            Assert.NotNull(response.IdToken);
        }

        [Fact]
        public async Task SerializeIdentityTokenAsync_ExpirationDateIsInferredFromCurrentDatetime()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnSerializeIdentityToken = context =>
                {
                    // Assert
                    Assert.NotNull(context.Ticket.Properties.IssuedUtc);
                    Assert.NotNull(context.Ticket.Properties.ExpiresUtc);

                    Assert.Equal(context.Ticket.Properties.IssuedUtc +
                                 context.Options.IdentityTokenLifetime,
                        context.Ticket.Properties.ExpiresUtc);

                    return Task.CompletedTask;
                };

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
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                GrantType = OpenIdConnectConstants.GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w",
                Scope = OpenIdConnectConstants.Scopes.OpenId
            });

            // Assert
            Assert.NotNull(response.IdToken);
        }

        [Fact]
        public async Task SerializeIdentityTokenAsync_ExpirationDateCanBeOverridenFromUserCode()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnSerializeIdentityToken = context =>
                {
                    // Assert
                    Assert.NotNull(context.Ticket.Properties.IssuedUtc);
                    Assert.NotNull(context.Ticket.Properties.ExpiresUtc);

                    Assert.Equal(context.Ticket.Properties.IssuedUtc + TimeSpan.FromDays(42),
                                 context.Ticket.Properties.ExpiresUtc);

                    return Task.CompletedTask;
                };

                options.Provider.OnValidateTokenRequest = context =>
                {
                    context.Skip();

                    return Task.CompletedTask;
                };

                options.Provider.OnHandleTokenRequest = context =>
                {
                    var identity = new ClaimsIdentity(OpenIdConnectServerDefaults.AuthenticationScheme);
                    identity.AddClaim(OpenIdConnectConstants.Claims.Subject, "Bob le Magnifique");

                    var ticket = new AuthenticationTicket(
                        new ClaimsPrincipal(identity),
                        new AuthenticationProperties(),
                        OpenIdConnectServerDefaults.AuthenticationScheme);

                    ticket.SetIdentityTokenLifetime(TimeSpan.FromDays(42));

                    context.Validate(ticket);

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                GrantType = OpenIdConnectConstants.GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w",
                Scope = OpenIdConnectConstants.Scopes.OpenId
            });

            // Assert
            Assert.NotNull(response.IdToken);
        }

        [Fact]
        public async Task SerializeIdentityTokenAsync_ClaimsWithoutAppropriateDestinationAreIgnored()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnSerializeIdentityToken = context =>
                {
                    // Assert
                    Assert.Null(context.Ticket.Principal.GetClaim(OpenIdConnectConstants.Claims.GivenName));

                    return Task.CompletedTask;
                };

                options.Provider.OnValidateTokenRequest = context =>
                {
                    context.Skip();

                    return Task.CompletedTask;
                };

                options.Provider.OnHandleTokenRequest = context =>
                {
                    var identity = new ClaimsIdentity(OpenIdConnectServerDefaults.AuthenticationScheme);
                    identity.AddClaim(OpenIdConnectConstants.Claims.Subject, "Bob le Magnifique");
                    identity.AddClaim(OpenIdConnectConstants.Claims.GivenName, "Bob");

                    context.Validate(new ClaimsPrincipal(identity));

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                GrantType = OpenIdConnectConstants.GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w",
                Scope = OpenIdConnectConstants.Scopes.OpenId
            });

            // Assert
            Assert.NotNull(response.IdToken);
        }

        [Fact]
        public async Task SerializeIdentityTokenAsync_ClaimsWithAppropriateDestinationAreIncluded()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnSerializeIdentityToken = context =>
                {
                    // Assert
                    Assert.Equal("Bob", context.Ticket.Principal.GetClaim(OpenIdConnectConstants.Claims.GivenName));

                    return Task.CompletedTask;
                };

                options.Provider.OnValidateTokenRequest = context =>
                {
                    context.Skip();

                    return Task.CompletedTask;
                };

                options.Provider.OnHandleTokenRequest = context =>
                {
                    var identity = new ClaimsIdentity(OpenIdConnectServerDefaults.AuthenticationScheme);
                    identity.AddClaim(OpenIdConnectConstants.Claims.Subject, "Bob le Magnifique");
                    identity.AddClaim(OpenIdConnectConstants.Claims.GivenName, "Bob", OpenIdConnectConstants.Destinations.IdentityToken);

                    context.Validate(new ClaimsPrincipal(identity));

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                GrantType = OpenIdConnectConstants.GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w",
                Scope = OpenIdConnectConstants.Scopes.OpenId
            });

            // Assert
            Assert.NotNull(response.IdToken);
        }

        [Fact]
        public async Task SerializeIdentityTokenAsync_BasicPropertiesAreAutomaticallyAdded()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnSerializeIdentityToken = context =>
                {
                    // Assert
                    Assert.Equal(new[] { "Fabrikam" }, context.Ticket.GetPresenters());
                    Assert.NotNull(context.Ticket.GetTokenId());

                    return Task.CompletedTask;
                };

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
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
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
        public async Task SerializeIdentityTokenAsync_RemovesUnnecessaryProperties()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnSerializeIdentityToken = context =>
                {
                    // Assert
                    Assert.Null(context.Ticket.GetProperty(OpenIdConnectConstants.Properties.AccessTokenLifetime));
                    Assert.Null(context.Ticket.GetProperty(OpenIdConnectConstants.Properties.AuthorizationCodeLifetime));
                    Assert.Null(context.Ticket.GetProperty(OpenIdConnectConstants.Properties.CodeChallenge));
                    Assert.Null(context.Ticket.GetProperty(OpenIdConnectConstants.Properties.CodeChallengeMethod));
                    Assert.Null(context.Ticket.GetProperty(OpenIdConnectConstants.Properties.IdentityTokenLifetime));
                    Assert.Null(context.Ticket.GetProperty(OpenIdConnectConstants.Properties.OriginalRedirectUri));
                    Assert.Null(context.Ticket.GetProperty(OpenIdConnectConstants.Properties.RefreshTokenLifetime));
                    Assert.Null(context.Ticket.GetProperty(OpenIdConnectConstants.Properties.TokenUsage));

                    return Task.CompletedTask;
                };

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
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
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
        public async Task SerializeIdentityTokenAsync_IgnoresEncryptingKeys()
        {
            // Arrange
            var parameters = new RSAParameters
            {
                D = Convert.FromBase64String("Uj6NrYBnyddhlJefYEP2nleCntAKlWyIttJC4cJnNxNN+OT2fQXhpTXRwW4R5YIS3HDqK/Fg2yoYm+OTVntAAgRFKveRx/WKwFo6UpnJc5u3lElhFa7IfosO9qXjErpX9ruAVqipekDLwQ++KmVVdgH4PK/o//nEx5zklGCdlEJURZYJPs9/7g1cx3UwvPp8jM7LgZL5OZRNyI3Jz4efrwiI2/vd8P28lAbpv/Ao4NwUDq/WKEnZ8JYSjLEKnZCfbX1ZEwf0Ic48jEKHmi1WEwpru1fMPoYfakrsY/VEfatPiDs8a5HABP/KaXcM4AZsr7HbzqAaNycV2xgdZimGcQ=="),
                DP = Convert.FromBase64String("hi1e+0eQ/iYrfT4zpZVbx3dyfA7Ch/aujMt6nGMF+1LGaut86vDHM2JI0Gc2BKc+uPEu2bNAorhSmuSyGpfGYl0MYFQoVF/jyiGpzYPmhYpL5yLuN9jWAqNwjfstuRDLU9zTEfZnr3OSN85rZcgT7NUxlY8im1Y2TWYxGiEXw9E="),
                DQ = Convert.FromBase64String("laVNkWIbnSuGo7nAxyUSdL2sXU3GZWwItwzTG0IK/0woFjArtCxGgNXW+V+GhxT7iHGAVJJSBvJ65TXrUYuBmoWj2CsoUs2mzK8ax4zg3CXrU61esCsGUoS2owR4FXlhYPmoVnglGu89bH72eXKixZsuF7vKW19nG703BXYEaEU="),
                Exponent = Convert.FromBase64String("AQAB"),
                InverseQ = Convert.FromBase64String("dhzLDS4F5WYHX+vH4+uL3Ei/K5lxw2A/dBHGtbS2X54gm7vARl+FrptOFFwIjjmsLuTjttAq9K1EP/XZIq8bjW6dXJ/IytnobIPSFkclEeQlMi4/2VDMG5915J0DwnKO9M+B8F3JViUyMv0pvb+ub+HHDVFkIr7zooCmY25i77Q="),
                Modulus = Convert.FromBase64String("kXv7Pxf6mSf7mu6mPAOAoKAXl5kU7Q3h9zevC5i4Mm5bMk17XCh7ZvVxDzGA+1JmyxOX6sw3gMUl31FtIFlDhis8VnXKAPn8i1zrmebq+7QKzpE2GpoIpXjXbkPaHG/DbC67M1bux7/dE7lSUSifHRRLsbMUC2D4UahJ6miH2iPFNFyoa6CLtwosD8tIJKwmZ9r9zfqc9BrVGu24lZySjTSRttpLaTkgkBjxHmYhinKNEtj9wUfi1S1wPJUvf+roc6o+7jeBBV3EXJCsb6XCCXI7/e3umWp19odeRShXLQNQbNuuVC7yre4iidUDrWJ1jiaB06svUG+fVEi4FCMvEQ=="),
                P = Convert.FromBase64String("xQGczmp4qD7Sez/ZqgW+O4cciTHvSqJqJUSdDd2l1Pd/szQ8avvzorrbSWOIULyv6eJb32+HuyLgy6rTSJ6THFobAnUv4ZTR7EGK26AJmP/BhD+3G+n21+4fzfbAxpHihkCYmO8aEl8fm/r4qPVXmCzFoXDZLMNIxFsdEXiFRS0="),
                Q = Convert.FromBase64String("vQy5C++AzF+TRh6qwbKzOqt87ZHEHidIAh6ivRNewjzIgCWXpseVl7DimY1YdViOnw1VI7xY+EyiyTanq5caTqqB3KcDm2t40bJfrZuUcn/5puRIh1bKNDwIMLsuNCrjHmDlNbocqpYMOh0Pgw7ARNbqrnPjWsYGJPuMNFpax/U=")
            };

            var credentials = new EncryptingCredentials(
                new RsaSecurityKey(parameters),
                SecurityAlgorithms.RsaOAEP,
                SecurityAlgorithms.Aes256CbcHmacSha512);

            var server = CreateAuthorizationServer(options =>
            {
                options.EncryptingCredentials.AddKey(new SymmetricSecurityKey(new byte[256 / 8]));
                options.EncryptingCredentials.Add(credentials);

                options.Provider.OnSerializeIdentityToken = context =>
                {
                    // Assert
                    Assert.Null(context.EncryptingCredentials);

                    return Task.CompletedTask;
                };

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
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
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
        public async Task SerializeIdentityTokenAsync_IgnoresSymmetricSigningKeys()
        {
            // Arrange
            var credentials = new SigningCredentials(
                new SymmetricSecurityKey(new byte[256 / 8]),
                SecurityAlgorithms.HmacSha256);

            var server = CreateAuthorizationServer(options =>
            {
                options.SigningCredentials.Insert(0, credentials);

                options.Provider.OnSerializeIdentityToken = context =>
                {
                    // Assert
                    Assert.NotSame(credentials, context.SigningCredentials);
                    Assert.Same(context.Options.SigningCredentials[1], context.SigningCredentials);
                    Assert.IsType<X509SecurityKey>(context.SigningCredentials.Key);

                    return Task.CompletedTask;
                };

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
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
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
        public async Task SerializeIdentityTokenAsync_UsesAsymmetricSigningKey()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnSerializeIdentityToken = context =>
                {
                    // Assert
                    Assert.Same(context.Options.SigningCredentials[0], context.SigningCredentials);
                    Assert.IsType<X509SecurityKey>(context.SigningCredentials.Key);

                    return Task.CompletedTask;
                };

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
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
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
        public async Task SerializeIdentityTokenAsync_AllowsHandlingSerialization()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnSerializeIdentityToken = context =>
                {
                    context.IdentityToken = "identity_token";
                    context.HandleSerialization();

                    return Task.CompletedTask;
                };

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
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                GrantType = OpenIdConnectConstants.GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w",
                Scope = OpenIdConnectConstants.Scopes.OpenId
            });

            // Assert
            Assert.Equal("identity_token", response.IdToken);
        }

        [Fact]
        public async Task SerializeIdentityTokenAsync_ThrowsAnExceptionForNullSecurityTokenHandler()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnSerializeIdentityToken = context =>
                {
                    context.SecurityTokenHandler = null;

                    return Task.CompletedTask;
                };

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
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act and assert
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
            {
                return client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
                {
                    GrantType = OpenIdConnectConstants.GrantTypes.Password,
                    Username = "johndoe",
                    Password = "A3ddj3w",
                    Scope = OpenIdConnectConstants.Scopes.OpenId
                });
            });

            Assert.Equal("A security token handler must be provided.", exception.Message);
        }

        [Theory]
        [InlineData("code id_token")]
        [InlineData("code id_token token")]
        [InlineData("id_token")]
        [InlineData("id_token token")]
        public async Task SerializeIdentityTokenAsync_MissingSigningCredentialsCauseAnException(string type)
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.IdentityTokenHandler = Mock.Of<JwtSecurityTokenHandler>();

                options.Provider.OnSerializeIdentityToken = context =>
                {
                    context.SigningCredentials = null;

                    return Task.CompletedTask;
                };

                options.Provider.OnValidateAuthorizationRequest = context =>
                {
                    context.Validate();

                    return Task.CompletedTask;
                };

                options.Provider.OnHandleAuthorizationRequest = context =>
                {
                    var identity = new ClaimsIdentity(OpenIdConnectServerDefaults.AuthenticationScheme);
                    identity.AddClaim(OpenIdConnectConstants.Claims.Subject, "Bob le Magnifique");

                    context.Validate(new ClaimsPrincipal(identity));

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act and assert
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
            {
                return client.PostAsync(AuthorizationEndpoint, new OpenIdConnectRequest
                {
                    ClientId = "Fabrikam",
                    Nonce = "n-0S6_WzA2Mj",
                    RedirectUri = "http://www.fabrikam.com/path",
                    ResponseType = type,
                    Scope = OpenIdConnectConstants.Scopes.OpenId
                });
            });

            Assert.Equal("A signing key must be provided.", exception.Message);
        }

        [Fact]
        public async Task SerializeIdentityTokenAsync_UsesIdentityTokenHandler()
        {
            // Arrange
            var format = new Mock<JwtSecurityTokenHandler>();
            format.Setup(mock => mock.CreateEncodedJwt(It.IsAny<SecurityTokenDescriptor>()))
                .Returns("7F82F1A3-8C9F-489F-B838-4B644B7C92B2")
                .Verifiable();

            var server = CreateAuthorizationServer(options =>
            {
                options.IdentityTokenHandler = format.Object;

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
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                GrantType = OpenIdConnectConstants.GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w",
                Scope = OpenIdConnectConstants.Scopes.OpenId
            });

            // Assert
            Assert.Equal("7F82F1A3-8C9F-489F-B838-4B644B7C92B2", response.IdToken);
            format.Verify(mock => mock.CreateEncodedJwt(It.IsAny<SecurityTokenDescriptor>()), Times.Once());
        }

        [Fact]
        public async Task SerializeRefreshTokenAsync_ExpirationDateIsNotAddedWhenLifetimeIsNull()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.RefreshTokenLifetime = null;

                options.Provider.OnSerializeRefreshToken = context =>
                {
                    // Assert
                    Assert.NotNull(context.Ticket.Properties.IssuedUtc);
                    Assert.Null(context.Ticket.Properties.ExpiresUtc);

                    return Task.CompletedTask;
                };

                options.Provider.OnValidateTokenRequest = context =>
                {
                    context.Skip();

                    return Task.CompletedTask;
                };

                options.Provider.OnHandleTokenRequest = context =>
                {
                    var identity = new ClaimsIdentity(OpenIdConnectServerDefaults.AuthenticationScheme);
                    identity.AddClaim(OpenIdConnectConstants.Claims.Subject, "Bob le Magnifique");

                    var ticket = new AuthenticationTicket(
                        new ClaimsPrincipal(identity),
                        new AuthenticationProperties(),
                        OpenIdConnectServerDefaults.AuthenticationScheme);

                    ticket.SetScopes(OpenIdConnectConstants.Scopes.OfflineAccess);

                    context.Validate(ticket);

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                GrantType = OpenIdConnectConstants.GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w",
                Scope = OpenIdConnectConstants.Scopes.OfflineAccess
            });

            // Assert
            Assert.NotNull(response.RefreshToken);
        }

        [Fact]
        public async Task SerializeRefreshTokenAsync_ExpirationDateIsInferredFromCurrentDatetime()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnSerializeRefreshToken = context =>
                {
                    // Assert
                    Assert.NotNull(context.Ticket.Properties.IssuedUtc);
                    Assert.NotNull(context.Ticket.Properties.ExpiresUtc);

                    Assert.Equal(context.Ticket.Properties.IssuedUtc +
                                 context.Options.RefreshTokenLifetime,
                        context.Ticket.Properties.ExpiresUtc);

                    return Task.CompletedTask;
                };

                options.Provider.OnValidateTokenRequest = context =>
                {
                    context.Skip();

                    return Task.CompletedTask;
                };

                options.Provider.OnHandleTokenRequest = context =>
                {
                    var identity = new ClaimsIdentity(OpenIdConnectServerDefaults.AuthenticationScheme);
                    identity.AddClaim(OpenIdConnectConstants.Claims.Subject, "Bob le Magnifique");

                    var ticket = new AuthenticationTicket(
                        new ClaimsPrincipal(identity),
                        new AuthenticationProperties(),
                        OpenIdConnectServerDefaults.AuthenticationScheme);

                    ticket.SetScopes(OpenIdConnectConstants.Scopes.OfflineAccess);

                    context.Validate(ticket);

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                GrantType = OpenIdConnectConstants.GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w",
                Scope = OpenIdConnectConstants.Scopes.OfflineAccess
            });

            // Assert
            Assert.NotNull(response.RefreshToken);
        }

        [Fact]
        public async Task SerializeRefreshTokenAsync_ExpirationDateCanBeOverridenFromUserCode()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnSerializeRefreshToken = context =>
                {
                    // Assert
                    Assert.NotNull(context.Ticket.Properties.IssuedUtc);
                    Assert.NotNull(context.Ticket.Properties.ExpiresUtc);

                    Assert.Equal(context.Ticket.Properties.IssuedUtc + TimeSpan.FromDays(42),
                                 context.Ticket.Properties.ExpiresUtc);

                    return Task.CompletedTask;
                };

                options.Provider.OnValidateTokenRequest = context =>
                {
                    context.Skip();

                    return Task.CompletedTask;
                };

                options.Provider.OnHandleTokenRequest = context =>
                {
                    var identity = new ClaimsIdentity(OpenIdConnectServerDefaults.AuthenticationScheme);
                    identity.AddClaim(OpenIdConnectConstants.Claims.Subject, "Bob le Magnifique");

                    var ticket = new AuthenticationTicket(
                        new ClaimsPrincipal(identity),
                        new AuthenticationProperties(),
                        OpenIdConnectServerDefaults.AuthenticationScheme);

                    ticket.SetScopes(OpenIdConnectConstants.Scopes.OfflineAccess);
                    ticket.SetRefreshTokenLifetime(TimeSpan.FromDays(42));

                    context.Validate(ticket);

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                GrantType = OpenIdConnectConstants.GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w",
                Scope = OpenIdConnectConstants.Scopes.OfflineAccess
            });

            // Assert
            Assert.NotNull(response.RefreshToken);
        }

        [Fact]
        public async Task SerializeRefreshTokenAsync_BasicPropertiesAreAutomaticallyAdded()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnSerializeRefreshToken = context =>
                {
                    // Assert
                    Assert.Equal(new[] { "Fabrikam" }, context.Ticket.GetPresenters());
                    Assert.NotNull(context.Ticket.GetTokenId());

                    return Task.CompletedTask;
                };

                options.Provider.OnValidateTokenRequest = context =>
                {
                    context.Skip();

                    return Task.CompletedTask;
                };

                options.Provider.OnHandleTokenRequest = context =>
                {
                    var identity = new ClaimsIdentity(OpenIdConnectServerDefaults.AuthenticationScheme);
                    identity.AddClaim(OpenIdConnectConstants.Claims.Subject, "Bob le Magnifique");

                    var ticket = new AuthenticationTicket(
                        new ClaimsPrincipal(identity),
                        new AuthenticationProperties(),
                        OpenIdConnectServerDefaults.AuthenticationScheme);

                    ticket.SetScopes(OpenIdConnectConstants.Scopes.OfflineAccess);

                    context.Validate(ticket);

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
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
        public async Task SerializeRefreshTokenAsync_RemovesUnnecessaryProperties()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnSerializeRefreshToken = context =>
                {
                    // Assert
                    Assert.Null(context.Ticket.GetProperty(OpenIdConnectConstants.Properties.AuthorizationCodeLifetime));
                    Assert.Null(context.Ticket.GetProperty(OpenIdConnectConstants.Properties.CodeChallenge));
                    Assert.Null(context.Ticket.GetProperty(OpenIdConnectConstants.Properties.CodeChallengeMethod));
                    Assert.Null(context.Ticket.GetProperty(OpenIdConnectConstants.Properties.Nonce));
                    Assert.Null(context.Ticket.GetProperty(OpenIdConnectConstants.Properties.OriginalRedirectUri));
                    Assert.Null(context.Ticket.GetProperty(OpenIdConnectConstants.Properties.TokenUsage));

                    return Task.CompletedTask;
                };

                options.Provider.OnValidateTokenRequest = context =>
                {
                    context.Skip();

                    return Task.CompletedTask;
                };

                options.Provider.OnHandleTokenRequest = context =>
                {
                    var identity = new ClaimsIdentity(OpenIdConnectServerDefaults.AuthenticationScheme);
                    identity.AddClaim(OpenIdConnectConstants.Claims.Subject, "Bob le Magnifique");

                    var ticket = new AuthenticationTicket(
                        new ClaimsPrincipal(identity),
                        new AuthenticationProperties(),
                        OpenIdConnectServerDefaults.AuthenticationScheme);

                    ticket.SetScopes(OpenIdConnectConstants.Scopes.OfflineAccess);

                    context.Validate(ticket);

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
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
        public async Task SerializeRefreshTokenAsync_AllowsHandlingSerialization()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnSerializeRefreshToken = context =>
                {
                    context.RefreshToken = "refresh_token";
                    context.HandleSerialization();

                    return Task.CompletedTask;
                };

                options.Provider.OnValidateTokenRequest = context =>
                {
                    context.Skip();

                    return Task.CompletedTask;
                };

                options.Provider.OnHandleTokenRequest = context =>
                {
                    var identity = new ClaimsIdentity(OpenIdConnectServerDefaults.AuthenticationScheme);
                    identity.AddClaim(OpenIdConnectConstants.Claims.Subject, "Bob le Magnifique");

                    var ticket = new AuthenticationTicket(
                        new ClaimsPrincipal(identity),
                        new AuthenticationProperties(),
                        OpenIdConnectServerDefaults.AuthenticationScheme);

                    ticket.SetScopes(OpenIdConnectConstants.Scopes.OfflineAccess);

                    context.Validate(ticket);

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                GrantType = OpenIdConnectConstants.GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w",
                Scope = OpenIdConnectConstants.Scopes.OfflineAccess
            });

            // Assert
            Assert.Equal("refresh_token", response.RefreshToken);
        }

        [Fact]
        public async Task SerializeRefreshTokenAsync_ThrowsAnExceptionForNullDataFormat()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnSerializeRefreshToken = context =>
                {
                    context.DataFormat = null;

                    return Task.CompletedTask;
                };

                options.Provider.OnValidateTokenRequest = context =>
                {
                    context.Skip();

                    return Task.CompletedTask;
                };

                options.Provider.OnHandleTokenRequest = context =>
                {
                    var identity = new ClaimsIdentity(OpenIdConnectServerDefaults.AuthenticationScheme);
                    identity.AddClaim(OpenIdConnectConstants.Claims.Subject, "Bob le Magnifique");

                    var ticket = new AuthenticationTicket(
                        new ClaimsPrincipal(identity),
                        new AuthenticationProperties(),
                        OpenIdConnectServerDefaults.AuthenticationScheme);

                    ticket.SetScopes(OpenIdConnectConstants.Scopes.OfflineAccess);

                    context.Validate(ticket);

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act and assert
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
            {
                return client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
                {
                    GrantType = OpenIdConnectConstants.GrantTypes.Password,
                    Username = "johndoe",
                    Password = "A3ddj3w",
                    Scope = OpenIdConnectConstants.Scopes.OfflineAccess
                });
            });

            Assert.Equal("A data formatter must be provided.", exception.Message);
        }

        [Fact]
        public async Task SerializeRefreshTokenAsync_UsesRefreshTokenFormat()
        {
            // Arrange
            var format = new Mock<ISecureDataFormat<AuthenticationTicket>>();
            format.Setup(mock => mock.Protect(It.IsAny<AuthenticationTicket>()))
                .Returns("7F82F1A3-8C9F-489F-B838-4B644B7C92B2")
                .Verifiable();

            var server = CreateAuthorizationServer(options =>
            {
                options.RefreshTokenFormat = format.Object;

                options.Provider.OnValidateTokenRequest = context =>
                {
                    context.Skip();

                    return Task.CompletedTask;
                };

                options.Provider.OnHandleTokenRequest = context =>
                {
                    var identity = new ClaimsIdentity(OpenIdConnectServerDefaults.AuthenticationScheme);
                    identity.AddClaim(OpenIdConnectConstants.Claims.Subject, "Bob le Magnifique");

                    var ticket = new AuthenticationTicket(
                        new ClaimsPrincipal(identity),
                        new AuthenticationProperties(),
                        OpenIdConnectServerDefaults.AuthenticationScheme);

                    ticket.SetScopes(OpenIdConnectConstants.Scopes.OfflineAccess);

                    context.Validate(ticket);

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
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
        public async Task DeserializeAuthorizationCodeAsync_AllowsHandlingDeserialization()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnDeserializeAuthorizationCode = context =>
                {
                    // Assert
                    Assert.Equal("authorization_code", context.AuthorizationCode);

                    context.Ticket = new AuthenticationTicket(
                        new ClaimsPrincipal(),
                        new AuthenticationProperties(),
                        OpenIdConnectServerDefaults.AuthenticationScheme);

                    context.HandleDeserialization();

                    return Task.CompletedTask;
                };

                options.Provider.OnValidateIntrospectionRequest = context =>
                {
                    context.Skip();

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(IntrospectionEndpoint, new OpenIdConnectRequest
            {
                Token = "authorization_code",
                TokenTypeHint = OpenIdConnectConstants.TokenTypeHints.AuthorizationCode
            });

            // Assert
            Assert.True((bool) response[OpenIdConnectConstants.Claims.Active]);
        }

        [Fact]
        public async Task DeserializeAuthorizationCodeAsync_AllowsReturningNullTicket()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnDeserializeAuthorizationCode = context =>
                {
                    // Assert
                    Assert.Equal("authorization_code", context.AuthorizationCode);

                    context.Ticket = null;
                    context.HandleDeserialization();

                    return Task.CompletedTask;
                };

                options.Provider.OnValidateIntrospectionRequest = context =>
                {
                    context.Skip();

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(IntrospectionEndpoint, new OpenIdConnectRequest
            {
                Token = "authorization_code",
                TokenTypeHint = OpenIdConnectConstants.TokenTypeHints.AuthorizationCode
            });

            // Assert
            Assert.False((bool) response[OpenIdConnectConstants.Claims.Active]);
        }

        [Fact]
        public async Task DeserializeAuthorizationCodeAsync_ThrowsAnExceptionForNullDataFormat()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnDeserializeAuthorizationCode = context =>
                {
                    context.DataFormat = null;

                    return Task.CompletedTask;
                };

                options.Provider.OnValidateIntrospectionRequest = context =>
                {
                    context.Skip();

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act and assert
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
            {
                return client.PostAsync(IntrospectionEndpoint, new OpenIdConnectRequest
                {
                    Token = "authorization_code",
                    TokenTypeHint = OpenIdConnectConstants.TokenTypeHints.AuthorizationCode
                });
            });

            Assert.Equal("A data formatter must be provided.", exception.Message);
        }

        [Fact]
        public async Task DeserializeAuthorizationCodeAsync_UsesAuthorizationCodeFormat()
        {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(),
                new AuthenticationProperties(),
                OpenIdConnectServerDefaults.AuthenticationScheme);

            var format = new Mock<ISecureDataFormat<AuthenticationTicket>>();
            format.Setup(mock => mock.Unprotect("7F82F1A3-8C9F-489F-B838-4B644B7C92B2"))
                .Returns(ticket)
                .Verifiable();

            var server = CreateAuthorizationServer(options =>
            {
                options.AuthorizationCodeFormat = format.Object;

                options.Provider.OnValidateIntrospectionRequest = context =>
                {
                    context.Skip();

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(IntrospectionEndpoint, new OpenIdConnectRequest
            {
                Token = "7F82F1A3-8C9F-489F-B838-4B644B7C92B2",
                TokenTypeHint = OpenIdConnectConstants.TokenTypeHints.AuthorizationCode
            });

            // Assert
            Assert.True((bool) response[OpenIdConnectConstants.Claims.Active]);
            format.Verify(mock => mock.Unprotect("7F82F1A3-8C9F-489F-B838-4B644B7C92B2"), Times.Once());
        }

        [Fact]
        public async Task DeserializeAccessTokenAsync_AllowsHandlingDeserialization()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnDeserializeAccessToken = context =>
                {
                    // Assert
                    Assert.Equal("access_token", context.AccessToken);

                    context.Ticket = new AuthenticationTicket(
                        new ClaimsPrincipal(),
                        new AuthenticationProperties(),
                        OpenIdConnectServerDefaults.AuthenticationScheme);

                    context.HandleDeserialization();

                    return Task.CompletedTask;
                };

                options.Provider.OnValidateIntrospectionRequest = context =>
                {
                    context.Skip();

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(IntrospectionEndpoint, new OpenIdConnectRequest
            {
                Token = "access_token",
                TokenTypeHint = OpenIdConnectConstants.TokenTypeHints.AccessToken
            });

            // Assert
            Assert.True((bool) response[OpenIdConnectConstants.Claims.Active]);
        }

        [Fact]
        public async Task DeserializeAccessTokenAsync_AllowsReturningNullTicket()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnDeserializeAccessToken = context =>
                {
                    // Assert
                    Assert.Equal("access_token", context.AccessToken);

                    context.Ticket = null;
                    context.HandleDeserialization();

                    return Task.CompletedTask;
                };

                options.Provider.OnValidateIntrospectionRequest = context =>
                {
                    context.Skip();

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(IntrospectionEndpoint, new OpenIdConnectRequest
            {
                Token = "access_token",
                TokenTypeHint = OpenIdConnectConstants.TokenTypeHints.AccessToken
            });

            // Assert
            Assert.False((bool) response[OpenIdConnectConstants.Claims.Active]);
        }

        [Fact]
        public async Task DeserializeAccessTokenAsync_ThrowsAnExceptionForNullDataFormat()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnDeserializeAccessToken = context =>
                {
                    context.SecurityTokenHandler = null;
                    context.DataFormat = null;

                    return Task.CompletedTask;
                };

                options.Provider.OnValidateIntrospectionRequest = context =>
                {
                    context.Skip();

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act and assert
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
            {
                return client.PostAsync(IntrospectionEndpoint, new OpenIdConnectRequest
                {
                    Token = "access_token",
                    TokenTypeHint = OpenIdConnectConstants.TokenTypeHints.AccessToken
                });
            });

            Assert.Equal("A security token handler or data formatter must be provided.", exception.Message);
        }

        [Fact]
        public async Task DeserializeAccessTokenAsync_IgnoresAsymmetricEncryptingKeys()
        {
            // Arrange
            var parameters = new RSAParameters
            {
                D = Convert.FromBase64String("Uj6NrYBnyddhlJefYEP2nleCntAKlWyIttJC4cJnNxNN+OT2fQXhpTXRwW4R5YIS3HDqK/Fg2yoYm+OTVntAAgRFKveRx/WKwFo6UpnJc5u3lElhFa7IfosO9qXjErpX9ruAVqipekDLwQ++KmVVdgH4PK/o//nEx5zklGCdlEJURZYJPs9/7g1cx3UwvPp8jM7LgZL5OZRNyI3Jz4efrwiI2/vd8P28lAbpv/Ao4NwUDq/WKEnZ8JYSjLEKnZCfbX1ZEwf0Ic48jEKHmi1WEwpru1fMPoYfakrsY/VEfatPiDs8a5HABP/KaXcM4AZsr7HbzqAaNycV2xgdZimGcQ=="),
                DP = Convert.FromBase64String("hi1e+0eQ/iYrfT4zpZVbx3dyfA7Ch/aujMt6nGMF+1LGaut86vDHM2JI0Gc2BKc+uPEu2bNAorhSmuSyGpfGYl0MYFQoVF/jyiGpzYPmhYpL5yLuN9jWAqNwjfstuRDLU9zTEfZnr3OSN85rZcgT7NUxlY8im1Y2TWYxGiEXw9E="),
                DQ = Convert.FromBase64String("laVNkWIbnSuGo7nAxyUSdL2sXU3GZWwItwzTG0IK/0woFjArtCxGgNXW+V+GhxT7iHGAVJJSBvJ65TXrUYuBmoWj2CsoUs2mzK8ax4zg3CXrU61esCsGUoS2owR4FXlhYPmoVnglGu89bH72eXKixZsuF7vKW19nG703BXYEaEU="),
                Exponent = Convert.FromBase64String("AQAB"),
                InverseQ = Convert.FromBase64String("dhzLDS4F5WYHX+vH4+uL3Ei/K5lxw2A/dBHGtbS2X54gm7vARl+FrptOFFwIjjmsLuTjttAq9K1EP/XZIq8bjW6dXJ/IytnobIPSFkclEeQlMi4/2VDMG5915J0DwnKO9M+B8F3JViUyMv0pvb+ub+HHDVFkIr7zooCmY25i77Q="),
                Modulus = Convert.FromBase64String("kXv7Pxf6mSf7mu6mPAOAoKAXl5kU7Q3h9zevC5i4Mm5bMk17XCh7ZvVxDzGA+1JmyxOX6sw3gMUl31FtIFlDhis8VnXKAPn8i1zrmebq+7QKzpE2GpoIpXjXbkPaHG/DbC67M1bux7/dE7lSUSifHRRLsbMUC2D4UahJ6miH2iPFNFyoa6CLtwosD8tIJKwmZ9r9zfqc9BrVGu24lZySjTSRttpLaTkgkBjxHmYhinKNEtj9wUfi1S1wPJUvf+roc6o+7jeBBV3EXJCsb6XCCXI7/e3umWp19odeRShXLQNQbNuuVC7yre4iidUDrWJ1jiaB06svUG+fVEi4FCMvEQ=="),
                P = Convert.FromBase64String("xQGczmp4qD7Sez/ZqgW+O4cciTHvSqJqJUSdDd2l1Pd/szQ8avvzorrbSWOIULyv6eJb32+HuyLgy6rTSJ6THFobAnUv4ZTR7EGK26AJmP/BhD+3G+n21+4fzfbAxpHihkCYmO8aEl8fm/r4qPVXmCzFoXDZLMNIxFsdEXiFRS0="),
                Q = Convert.FromBase64String("vQy5C++AzF+TRh6qwbKzOqt87ZHEHidIAh6ivRNewjzIgCWXpseVl7DimY1YdViOnw1VI7xY+EyiyTanq5caTqqB3KcDm2t40bJfrZuUcn/5puRIh1bKNDwIMLsuNCrjHmDlNbocqpYMOh0Pgw7ARNbqrnPjWsYGJPuMNFpax/U=")
            };

            var credentials = new EncryptingCredentials(
                new RsaSecurityKey(parameters),
                SecurityAlgorithms.RsaOAEP,
                SecurityAlgorithms.Aes256CbcHmacSha512);

            var server = CreateAuthorizationServer(options =>
            {
                options.EncryptingCredentials.Add(credentials);
                options.EncryptingCredentials.AddKey(new SymmetricSecurityKey(new byte[256 / 8]));

                options.Provider.OnDeserializeAccessToken = context =>
                {
                    var keys = context.TokenValidationParameters.TokenDecryptionKeys.ToArray();

                    // Assert
                    Assert.Single(keys);
                    Assert.NotSame(credentials, keys[0]);
                    Assert.Same(context.Options.EncryptingCredentials[1].Key, keys[0]);
                    Assert.IsType<SymmetricSecurityKey>(keys[0]);

                    context.Ticket = new AuthenticationTicket(
                        new ClaimsPrincipal(),
                        new AuthenticationProperties(),
                        OpenIdConnectServerDefaults.AuthenticationScheme);

                    context.HandleDeserialization();

                    return Task.CompletedTask;
                };

                options.Provider.OnValidateIntrospectionRequest = context =>
                {
                    context.Skip();

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(IntrospectionEndpoint, new OpenIdConnectRequest
            {
                Token = "access_token",
                TokenTypeHint = OpenIdConnectConstants.TokenTypeHints.AccessToken
            });

            // Assert
            Assert.True((bool) response[OpenIdConnectConstants.Claims.Active]);
        }

        [Fact]
        public async Task DeserializeAccessTokenAsync_UsesAccessTokenFormatByDefault()
        {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(),
                new AuthenticationProperties(),
                OpenIdConnectServerDefaults.AuthenticationScheme);

            var format = new Mock<ISecureDataFormat<AuthenticationTicket>>();
            format.Setup(mock => mock.Unprotect("7F82F1A3-8C9F-489F-B838-4B644B7C92B2"))
                .Returns(ticket)
                .Verifiable();

            var server = CreateAuthorizationServer(options =>
            {
                options.AccessTokenFormat = format.Object;

                options.Provider.OnValidateIntrospectionRequest = context =>
                {
                    context.Skip();

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(IntrospectionEndpoint, new OpenIdConnectRequest
            {
                Token = "7F82F1A3-8C9F-489F-B838-4B644B7C92B2",
                TokenTypeHint = OpenIdConnectConstants.TokenTypeHints.AccessToken
            });

            // Assert
            Assert.True((bool) response[OpenIdConnectConstants.Claims.Active]);
            format.Verify(mock => mock.Unprotect("7F82F1A3-8C9F-489F-B838-4B644B7C92B2"), Times.Once());
        }

        [Fact]
        public async Task DeserializeAccessTokenAsync_UsesAccessTokenHandlerWhenRegistered()
        {
            // Arrange
            var token = Mock.Of<SecurityToken>(mock =>
                mock.ValidFrom == DateTime.UtcNow.AddDays(-1) &&
                mock.ValidTo == DateTime.UtcNow.AddDays(1));

            var identity = new ClaimsIdentity(OpenIdConnectServerDefaults.AuthenticationScheme);
            identity.AddClaim(OpenIdConnectConstants.Claims.TokenUsage, OpenIdConnectConstants.TokenUsages.AccessToken);

            var format = new Mock<JwtSecurityTokenHandler>();

            format.Setup(mock => mock.CanReadToken("7F82F1A3-8C9F-489F-B838-4B644B7C92B2"))
                .Returns(true)
                .Verifiable();

            format.Setup(mock => mock.ValidateToken(
                    "7F82F1A3-8C9F-489F-B838-4B644B7C92B2",
                    It.IsAny<TokenValidationParameters>(), out token))
                .Returns(new ClaimsPrincipal(identity))
                .Verifiable();

            var server = CreateAuthorizationServer(options =>
            {
                options.AccessTokenHandler = format.Object;

                options.Provider.OnValidateIntrospectionRequest = context =>
                {
                    context.Skip();

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(IntrospectionEndpoint, new OpenIdConnectRequest
            {
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
        public async Task DeserializeAccessTokenAsync_ReturnsNullForInvalidTokenType()
        {
            // Arrange
            var token = Mock.Of<SecurityToken>(mock =>
                mock.ValidFrom == DateTime.UtcNow.AddDays(-1) &&
                mock.ValidTo == DateTime.UtcNow.AddDays(1));

            var identity = new ClaimsIdentity(OpenIdConnectServerDefaults.AuthenticationScheme);
            identity.AddClaim(OpenIdConnectConstants.Claims.TokenUsage, OpenIdConnectConstants.TokenUsages.IdToken);

            var format = new Mock<JwtSecurityTokenHandler>();

            format.Setup(mock => mock.CanReadToken("7F82F1A3-8C9F-489F-B838-4B644B7C92B2"))
                .Returns(true)
                .Verifiable();

            format.Setup(mock => mock.ValidateToken(
                "7F82F1A3-8C9F-489F-B838-4B644B7C92B2",
                It.IsAny<TokenValidationParameters>(), out token))
                .Returns(new ClaimsPrincipal(identity))
                .Verifiable();

            var server = CreateAuthorizationServer(options =>
            {
                options.AccessTokenHandler = format.Object;

                options.Provider.OnValidateIntrospectionRequest = context =>
                {
                    context.Skip();

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(IntrospectionEndpoint, new OpenIdConnectRequest
            {
                Token = "7F82F1A3-8C9F-489F-B838-4B644B7C92B2",
                TokenTypeHint = OpenIdConnectConstants.TokenTypeHints.AccessToken
            });

            // Assert
            Assert.False((bool) response[OpenIdConnectConstants.Claims.Active]);
        }

        [Fact]
        public async Task DeserializeIdentityTokenAsync_AllowsHandlingDeserialization()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnDeserializeIdentityToken = context =>
                {
                    // Assert
                    Assert.Equal("id_token", context.IdentityToken);

                    context.Ticket = new AuthenticationTicket(
                        new ClaimsPrincipal(),
                        new AuthenticationProperties(),
                        OpenIdConnectServerDefaults.AuthenticationScheme);

                    context.HandleDeserialization();

                    return Task.CompletedTask;
                };

                options.Provider.OnValidateIntrospectionRequest = context =>
                {
                    context.Skip();

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(IntrospectionEndpoint, new OpenIdConnectRequest
            {
                Token = "id_token",
                TokenTypeHint = OpenIdConnectConstants.TokenTypeHints.IdToken
            });

            // Assert
            Assert.True((bool) response[OpenIdConnectConstants.Claims.Active]);
        }

        [Fact]
        public async Task DeserializeIdentityTokenAsync_AllowsReturningNullTicket()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnDeserializeIdentityToken = context =>
                {
                    // Assert
                    Assert.Equal("id_token", context.IdentityToken);

                    context.Ticket = null;
                    context.HandleDeserialization();

                    return Task.CompletedTask;
                };

                options.Provider.OnValidateIntrospectionRequest = context =>
                {
                    context.Skip();

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(IntrospectionEndpoint, new OpenIdConnectRequest
            {
                Token = "id_token",
                TokenTypeHint = OpenIdConnectConstants.TokenTypeHints.IdToken
            });

            // Assert
            Assert.False((bool) response[OpenIdConnectConstants.Claims.Active]);
        }

        [Fact]
        public async Task DeserializeIdentityTokenAsync_ThrowsAnExceptionForNullSecurityTokenHandler()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnDeserializeIdentityToken = context =>
                {
                    context.SecurityTokenHandler = null;

                    return Task.CompletedTask;
                };

                options.Provider.OnValidateIntrospectionRequest = context =>
                {
                    context.Skip();

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act and assert
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
            {
                return client.PostAsync(IntrospectionEndpoint, new OpenIdConnectRequest
                {
                    Token = "id_token",
                    TokenTypeHint = OpenIdConnectConstants.TokenTypeHints.IdToken
                });
            });

            Assert.Equal("A security token handler must be provided.", exception.Message);
        }

        [Fact]
        public async Task DeserializeIdentityTokenAsync_IgnoresEncryptingKeys()
        {
            // Arrange
            var parameters = new RSAParameters
            {
                D = Convert.FromBase64String("Uj6NrYBnyddhlJefYEP2nleCntAKlWyIttJC4cJnNxNN+OT2fQXhpTXRwW4R5YIS3HDqK/Fg2yoYm+OTVntAAgRFKveRx/WKwFo6UpnJc5u3lElhFa7IfosO9qXjErpX9ruAVqipekDLwQ++KmVVdgH4PK/o//nEx5zklGCdlEJURZYJPs9/7g1cx3UwvPp8jM7LgZL5OZRNyI3Jz4efrwiI2/vd8P28lAbpv/Ao4NwUDq/WKEnZ8JYSjLEKnZCfbX1ZEwf0Ic48jEKHmi1WEwpru1fMPoYfakrsY/VEfatPiDs8a5HABP/KaXcM4AZsr7HbzqAaNycV2xgdZimGcQ=="),
                DP = Convert.FromBase64String("hi1e+0eQ/iYrfT4zpZVbx3dyfA7Ch/aujMt6nGMF+1LGaut86vDHM2JI0Gc2BKc+uPEu2bNAorhSmuSyGpfGYl0MYFQoVF/jyiGpzYPmhYpL5yLuN9jWAqNwjfstuRDLU9zTEfZnr3OSN85rZcgT7NUxlY8im1Y2TWYxGiEXw9E="),
                DQ = Convert.FromBase64String("laVNkWIbnSuGo7nAxyUSdL2sXU3GZWwItwzTG0IK/0woFjArtCxGgNXW+V+GhxT7iHGAVJJSBvJ65TXrUYuBmoWj2CsoUs2mzK8ax4zg3CXrU61esCsGUoS2owR4FXlhYPmoVnglGu89bH72eXKixZsuF7vKW19nG703BXYEaEU="),
                Exponent = Convert.FromBase64String("AQAB"),
                InverseQ = Convert.FromBase64String("dhzLDS4F5WYHX+vH4+uL3Ei/K5lxw2A/dBHGtbS2X54gm7vARl+FrptOFFwIjjmsLuTjttAq9K1EP/XZIq8bjW6dXJ/IytnobIPSFkclEeQlMi4/2VDMG5915J0DwnKO9M+B8F3JViUyMv0pvb+ub+HHDVFkIr7zooCmY25i77Q="),
                Modulus = Convert.FromBase64String("kXv7Pxf6mSf7mu6mPAOAoKAXl5kU7Q3h9zevC5i4Mm5bMk17XCh7ZvVxDzGA+1JmyxOX6sw3gMUl31FtIFlDhis8VnXKAPn8i1zrmebq+7QKzpE2GpoIpXjXbkPaHG/DbC67M1bux7/dE7lSUSifHRRLsbMUC2D4UahJ6miH2iPFNFyoa6CLtwosD8tIJKwmZ9r9zfqc9BrVGu24lZySjTSRttpLaTkgkBjxHmYhinKNEtj9wUfi1S1wPJUvf+roc6o+7jeBBV3EXJCsb6XCCXI7/e3umWp19odeRShXLQNQbNuuVC7yre4iidUDrWJ1jiaB06svUG+fVEi4FCMvEQ=="),
                P = Convert.FromBase64String("xQGczmp4qD7Sez/ZqgW+O4cciTHvSqJqJUSdDd2l1Pd/szQ8avvzorrbSWOIULyv6eJb32+HuyLgy6rTSJ6THFobAnUv4ZTR7EGK26AJmP/BhD+3G+n21+4fzfbAxpHihkCYmO8aEl8fm/r4qPVXmCzFoXDZLMNIxFsdEXiFRS0="),
                Q = Convert.FromBase64String("vQy5C++AzF+TRh6qwbKzOqt87ZHEHidIAh6ivRNewjzIgCWXpseVl7DimY1YdViOnw1VI7xY+EyiyTanq5caTqqB3KcDm2t40bJfrZuUcn/5puRIh1bKNDwIMLsuNCrjHmDlNbocqpYMOh0Pgw7ARNbqrnPjWsYGJPuMNFpax/U=")
            };

            var credentials = new EncryptingCredentials(
                new RsaSecurityKey(parameters),
                SecurityAlgorithms.RsaOAEP,
                SecurityAlgorithms.Aes256CbcHmacSha512);

            var server = CreateAuthorizationServer(options =>
            {
                options.EncryptingCredentials.AddKey(new SymmetricSecurityKey(new byte[256 / 8]));
                options.EncryptingCredentials.Add(credentials);

                options.Provider.OnDeserializeIdentityToken = context =>
                {
                    // Assert
                    Assert.Null(context.TokenValidationParameters.TokenDecryptionKey);
                    Assert.Null(context.TokenValidationParameters.TokenDecryptionKeys);

                    context.Ticket = new AuthenticationTicket(
                        new ClaimsPrincipal(),
                        new AuthenticationProperties(),
                        OpenIdConnectServerDefaults.AuthenticationScheme);

                    context.HandleDeserialization();

                    return Task.CompletedTask;
                };

                options.Provider.OnValidateIntrospectionRequest = context =>
                {
                    context.Skip();

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(IntrospectionEndpoint, new OpenIdConnectRequest
            {
                Token = "id_token",
                TokenTypeHint = OpenIdConnectConstants.TokenTypeHints.IdToken
            });

            // Assert
            Assert.True((bool) response[OpenIdConnectConstants.Claims.Active]);
        }

        [Fact]
        public async Task DeserializeIdentityTokenAsync_IgnoresSymmetricSigningKeys()
        {
            // Arrange
            var credentials = new SigningCredentials(
                new SymmetricSecurityKey(new byte[256 / 8]),
                SecurityAlgorithms.HmacSha256);

            var server = CreateAuthorizationServer(options =>
            {
                options.SigningCredentials.Insert(0, credentials);

                options.Provider.OnDeserializeIdentityToken = context =>
                {
                    var keys = context.TokenValidationParameters.IssuerSigningKeys.ToArray();

                    // Assert
                    Assert.Single(keys);
                    Assert.NotSame(credentials, keys[0]);
                    Assert.Same(context.Options.SigningCredentials[1].Key, keys[0]);
                    Assert.IsType<X509SecurityKey>(keys[0]);

                    context.Ticket = new AuthenticationTicket(
                        new ClaimsPrincipal(),
                        new AuthenticationProperties(),
                        OpenIdConnectServerDefaults.AuthenticationScheme);

                    context.HandleDeserialization();

                    return Task.CompletedTask;
                };

                options.Provider.OnValidateIntrospectionRequest = context =>
                {
                    context.Skip();

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(IntrospectionEndpoint, new OpenIdConnectRequest
            {
                Token = "id_token",
                TokenTypeHint = OpenIdConnectConstants.TokenTypeHints.IdToken
            });

            // Assert
            Assert.True((bool) response[OpenIdConnectConstants.Claims.Active]);
        }

        [Fact]
        public async Task DeserializeIdentityTokenAsync_UsesIdentityTokenHandler()
        {
            // Arrange
            var token = Mock.Of<SecurityToken>(mock =>
                mock.ValidFrom == DateTime.UtcNow.AddDays(-1) &&
                mock.ValidTo == DateTime.UtcNow.AddDays(1));

            var identity = new ClaimsIdentity(OpenIdConnectServerDefaults.AuthenticationScheme);
            identity.AddClaim(OpenIdConnectConstants.Claims.TokenUsage, OpenIdConnectConstants.TokenUsages.IdToken);

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

            var server = CreateAuthorizationServer(options =>
            {
                options.IdentityTokenHandler = format.Object;

                options.Provider.OnValidateIntrospectionRequest = context =>
                {
                    context.Skip();

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(IntrospectionEndpoint, new OpenIdConnectRequest
            {
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
        public async Task DeserializeIdentityTokenAsync_ReturnsNullForInvalidTokenType()
        {
            // Arrange
            var token = Mock.Of<SecurityToken>(mock =>
                mock.ValidFrom == DateTime.UtcNow.AddDays(-1) &&
                mock.ValidTo == DateTime.UtcNow.AddDays(1));

            var identity = new ClaimsIdentity(OpenIdConnectServerDefaults.AuthenticationScheme);
            identity.AddClaim(OpenIdConnectConstants.Claims.TokenUsage, OpenIdConnectConstants.TokenUsages.AccessToken);

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

            var server = CreateAuthorizationServer(options =>
            {
                options.IdentityTokenHandler = format.Object;

                options.Provider.OnValidateIntrospectionRequest = context =>
                {
                    context.Skip();

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(IntrospectionEndpoint, new OpenIdConnectRequest
            {
                Token = "7F82F1A3-8C9F-489F-B838-4B644B7C92B2",
                TokenTypeHint = OpenIdConnectConstants.TokenTypeHints.IdToken
            });

            // Assert
            Assert.False((bool) response[OpenIdConnectConstants.Claims.Active]);
        }

        [Fact]
        public async Task DeserializeRefreshTokenAsync_AllowsHandlingDeserialization()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnDeserializeRefreshToken = context =>
                {
                    // Assert
                    Assert.Equal("refresh_token", context.RefreshToken);

                    context.Ticket = new AuthenticationTicket(
                        new ClaimsPrincipal(),
                        new AuthenticationProperties(),
                        OpenIdConnectServerDefaults.AuthenticationScheme);

                    context.HandleDeserialization();

                    return Task.CompletedTask;
                };

                options.Provider.OnValidateIntrospectionRequest = context =>
                {
                    context.Skip();

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(IntrospectionEndpoint, new OpenIdConnectRequest
            {
                Token = "refresh_token",
                TokenTypeHint = OpenIdConnectConstants.TokenTypeHints.RefreshToken
            });

            // Assert
            Assert.True((bool) response[OpenIdConnectConstants.Claims.Active]);
        }

        [Fact]
        public async Task DeserializeRefreshTokenAsync_AllowsReturningNullTicket()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnDeserializeRefreshToken = context =>
                {
                    // Assert
                    Assert.Equal("refresh_token", context.RefreshToken);

                    context.Ticket = null;
                    context.HandleDeserialization();

                    return Task.CompletedTask;
                };

                options.Provider.OnValidateIntrospectionRequest = context =>
                {
                    context.Skip();

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(IntrospectionEndpoint, new OpenIdConnectRequest
            {
                Token = "refresh_token",
                TokenTypeHint = OpenIdConnectConstants.TokenTypeHints.RefreshToken
            });

            // Assert
            Assert.False((bool) response[OpenIdConnectConstants.Claims.Active]);
        }

        [Fact]
        public async Task DeserializeRefreshTokenAsync_ThrowsAnExceptionForNullDataFormat()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider.OnDeserializeRefreshToken = context =>
                {
                    context.DataFormat = null;

                    return Task.CompletedTask;
                };

                options.Provider.OnValidateIntrospectionRequest = context =>
                {
                    context.Skip();

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
            {
                return client.PostAsync(IntrospectionEndpoint, new OpenIdConnectRequest
                {
                    Token = "refresh_token",
                    TokenTypeHint = OpenIdConnectConstants.TokenTypeHints.RefreshToken
                });
            });

            Assert.Equal("A data formatter must be provided.", exception.Message);
        }

        [Fact]
        public async Task DeserializeRefreshTokenAsync_UsesRefreshTokenFormat()
        {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(),
                new AuthenticationProperties(),
                OpenIdConnectServerDefaults.AuthenticationScheme);

            var format = new Mock<ISecureDataFormat<AuthenticationTicket>>();
            format.Setup(mock => mock.Unprotect("7F82F1A3-8C9F-489F-B838-4B644B7C92B2"))
                .Returns(ticket)
                .Verifiable();

            var server = CreateAuthorizationServer(options =>
            {
                options.RefreshTokenFormat = format.Object;

                options.Provider.OnValidateIntrospectionRequest = context =>
                {
                    context.Skip();

                    return Task.CompletedTask;
                };
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(IntrospectionEndpoint, new OpenIdConnectRequest
            {
                Token = "7F82F1A3-8C9F-489F-B838-4B644B7C92B2",
                TokenTypeHint = OpenIdConnectConstants.TokenTypeHints.RefreshToken
            });

            // Assert
            Assert.True((bool) response[OpenIdConnectConstants.Claims.Active]);
            format.Verify(mock => mock.Unprotect("7F82F1A3-8C9F-489F-B838-4B644B7C92B2"), Times.Once());
        }
    }
}
