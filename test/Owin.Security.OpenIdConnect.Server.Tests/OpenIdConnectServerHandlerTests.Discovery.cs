using System;
using System.IdentityModel.Tokens;
using System.Security.Cryptography;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Client;
using AspNet.Security.OpenIdConnect.Primitives;
using Microsoft.IdentityModel.Protocols;
using Microsoft.Owin;
using Moq;
using Newtonsoft.Json;
using Owin.Security.OpenIdConnect.Extensions;
using Xunit;
using static System.Net.Http.HttpMethod;

namespace Owin.Security.OpenIdConnect.Server.Tests {
    public partial class OpenIdConnectServerHandlerTests {
        [Theory]
        [InlineData(nameof(Delete))]
        [InlineData(nameof(Head))]
        [InlineData(nameof(Options))]
        [InlineData(nameof(Post))]
        [InlineData(nameof(Put))]
        [InlineData(nameof(Trace))]
        public async Task InvokeConfigurationEndpointAsync_UnexpectedMethodReturnsAnError(string method) {
            // Arrange
            var server = CreateAuthorizationServer();

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.SendAsync(method, ConfigurationEndpoint, new OpenIdConnectRequest());

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal("Invalid HTTP method: make sure to use GET.", response.ErrorDescription);
        }

        [Theory]
        [InlineData("custom_error", null, null)]
        [InlineData("custom_error", "custom_description", null)]
        [InlineData("custom_error", "custom_description", "custom_uri")]
        [InlineData(null, "custom_description", null)]
        [InlineData(null, "custom_description", "custom_uri")]
        [InlineData(null, null, "custom_uri")]
        [InlineData(null, null, null)]
        public async Task InvokeConfigurationEndpointAsync_ExtractConfigurationRequest_AllowsRejectingRequest(string error, string description, string uri) {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnExtractConfigurationRequest = context => {
                    context.Reject(error, description, uri);

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.GetAsync(ConfigurationEndpoint);

            // Assert
            Assert.Equal(error ?? OpenIdConnectConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal(description, response.ErrorDescription);
            Assert.Equal(uri, response.ErrorUri);
        }

        [Fact]
        public async Task InvokeConfigurationEndpointAsync_ExtractConfigurationRequest_AllowsHandlingResponse() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnExtractConfigurationRequest = context => {
                    context.HandleResponse();

                    context.OwinContext.Response.Headers["Content-Type"] = "application/json";

                    return context.OwinContext.Response.WriteAsync(JsonConvert.SerializeObject(new {
                        name = "Bob le Bricoleur"
                    }));
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.GetAsync(ConfigurationEndpoint);

            // Assert
            Assert.Equal("Bob le Bricoleur", (string) response["name"]);
        }

        [Fact]
        public async Task InvokeConfigurationEndpointAsync_ExtractConfigurationRequest_AllowsSkippingToNextMiddleware() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnExtractConfigurationRequest = context => {
                    context.SkipToNextMiddleware();

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.GetAsync(ConfigurationEndpoint);

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
        public async Task InvokeConfigurationEndpointAsync_ValidateConfigurationRequest_AllowsRejectingRequest(string error, string description, string uri) {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnValidateConfigurationRequest = context => {
                    context.Reject(error, description, uri);

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.GetAsync(ConfigurationEndpoint);

            // Assert
            Assert.Equal(error ?? OpenIdConnectConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal(description, response.ErrorDescription);
            Assert.Equal(uri, response.ErrorUri);
        }

        [Fact]
        public async Task InvokeConfigurationEndpointAsync_ValidateConfigurationRequest_AllowsHandlingResponse() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnValidateConfigurationRequest = context => {
                    context.HandleResponse();

                    context.OwinContext.Response.Headers["Content-Type"] = "application/json";

                    return context.OwinContext.Response.WriteAsync(JsonConvert.SerializeObject(new {
                        name = "Bob le Magnifique"
                    }));
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.GetAsync(ConfigurationEndpoint);

            // Assert
            Assert.Equal("Bob le Magnifique", (string) response["name"]);
        }

        [Fact]
        public async Task InvokeConfigurationEndpointAsync_ValidateConfigurationRequest_AllowsSkippingToNextMiddleware() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnValidateConfigurationRequest = context => {
                    context.SkipToNextMiddleware();

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.GetAsync(ConfigurationEndpoint);

            // Assert
            Assert.Equal("Bob le Magnifique", (string) response["name"]);
        }

        [Fact]
        public async Task InvokeConfigurationEndpointAsync_IssuerIsAutomaticallyInferred() {
            // Arrange
            var server = CreateAuthorizationServer();

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.GetAsync(ConfigurationEndpoint);

            // Assert
            Assert.Equal(client.HttpClient.BaseAddress.AbsoluteUri,
                (string) response[OpenIdConnectConstants.Metadata.Issuer]);
        }

        [Fact]
        public async Task InvokeConfigurationEndpointAsync_RegisteredIssuerIsAlwaysPreferred() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Issuer = new Uri("https://www.fabrikam.com/");
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.GetAsync(ConfigurationEndpoint);

            // Assert
            Assert.Equal("https://www.fabrikam.com/",
                (string) response[OpenIdConnectConstants.Metadata.Issuer]);
        }

        [Fact]
        public async Task InvokeConfigurationEndpointAsync_EnabledEndpointsAreExposed() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Issuer = new Uri("https://www.fabrikam.com/");
                options.AuthorizationEndpointPath = new PathString("/path/authorization_endpoint");
                options.IntrospectionEndpointPath = new PathString("/path/introspection_endpoint");
                options.LogoutEndpointPath = new PathString("/path/logout_endpoint");
                options.RevocationEndpointPath = new PathString("/path/revocation_endpoint");
                options.TokenEndpointPath = new PathString("/path/token_endpoint");
                options.UserinfoEndpointPath = new PathString("/path/userinfo_endpoint");
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.GetAsync(ConfigurationEndpoint);

            // Assert
            Assert.Equal("https://www.fabrikam.com/path/authorization_endpoint",
                (string) response[OpenIdConnectConstants.Metadata.AuthorizationEndpoint]);

            Assert.Equal("https://www.fabrikam.com/path/introspection_endpoint",
                (string) response[OpenIdConnectConstants.Metadata.IntrospectionEndpoint]);

            Assert.Equal("https://www.fabrikam.com/path/logout_endpoint",
                (string) response[OpenIdConnectConstants.Metadata.EndSessionEndpoint]);

            Assert.Equal("https://www.fabrikam.com/path/revocation_endpoint",
                (string) response[OpenIdConnectConstants.Metadata.RevocationEndpoint]);

            Assert.Equal("https://www.fabrikam.com/path/token_endpoint",
                (string) response[OpenIdConnectConstants.Metadata.TokenEndpoint]);

            Assert.Equal("https://www.fabrikam.com/path/userinfo_endpoint",
                (string) response[OpenIdConnectConstants.Metadata.UserinfoEndpoint]);
        }

        [Fact]
        public async Task InvokeConfigurationEndpointAsync_GrantTypesIncludeImplicitWhenAuthorizationEndpointIsEnabled() {
            // Arrange
            var server = CreateAuthorizationServer();

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.GetAsync(ConfigurationEndpoint);
            var types = response[OpenIdConnectConstants.Metadata.GrantTypesSupported].Values<string>();

            // Assert
            Assert.Contains(OpenIdConnectConstants.GrantTypes.Implicit, types);
        }

        [Fact]
        public async Task InvokeConfigurationEndpointAsync_DefaultGrantTypesAreIncludedWhenTokenEndpointIsEnabled() {
            // Arrange
            var server = CreateAuthorizationServer();

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.GetAsync(ConfigurationEndpoint);
            var types = response[OpenIdConnectConstants.Metadata.GrantTypesSupported].Values<string>();

            // Assert
            Assert.Contains(OpenIdConnectConstants.GrantTypes.ClientCredentials, types);
            Assert.Contains(OpenIdConnectConstants.GrantTypes.Password, types);
            Assert.Contains(OpenIdConnectConstants.GrantTypes.RefreshToken, types);
        }

        [Fact]
        public async Task InvokeConfigurationEndpointAsync_DefaultResponseModesAreIncludedWhenAuthorizationEndpointIsEnabled() {
            // Arrange
            var server = CreateAuthorizationServer();

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.GetAsync(ConfigurationEndpoint);
            var modes = response[OpenIdConnectConstants.Metadata.ResponseModesSupported].Values<string>();

            // Assert
            Assert.Contains(OpenIdConnectConstants.ResponseModes.FormPost, modes);
            Assert.Contains(OpenIdConnectConstants.ResponseModes.Fragment, modes);
            Assert.Contains(OpenIdConnectConstants.ResponseModes.Query, modes);
        }

        [Fact]
        public async Task InvokeConfigurationEndpointAsync_DefaultResponseTypesAreIncludedWhenAuthorizationEndpointIsEnabled() {
            // Arrange
            var server = CreateAuthorizationServer();

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.GetAsync(ConfigurationEndpoint);
            var types = response[OpenIdConnectConstants.Metadata.ResponseTypesSupported].Values<string>();

            // Assert
            Assert.Contains(OpenIdConnectConstants.ResponseTypes.Token, types);
            Assert.Contains(OpenIdConnectConstants.ResponseTypes.IdToken, types);
            Assert.Contains(OpenIdConnectConstants.ResponseTypes.IdToken + ' ' +
                            OpenIdConnectConstants.ResponseTypes.Token, types);
        }

        [Fact]
        public async Task InvokeConfigurationEndpointAsync_DefaultResponseTypesAreIncludedWhenTokenEndpointIsEnabled() {
            // Arrange
            var server = CreateAuthorizationServer();

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.GetAsync(ConfigurationEndpoint);
            var types = response[OpenIdConnectConstants.Metadata.ResponseTypesSupported].Values<string>();

            // Assert
            Assert.Contains(
                OpenIdConnectConstants.ResponseTypes.Code + ' ' +
                OpenIdConnectConstants.ResponseTypes.Token, types);

            Assert.Contains(
                OpenIdConnectConstants.ResponseTypes.Code + ' ' +
                OpenIdConnectConstants.ResponseTypes.IdToken, types);

            Assert.Contains(
                OpenIdConnectConstants.ResponseTypes.Code + ' ' +
                OpenIdConnectConstants.ResponseTypes.IdToken + ' ' +
                OpenIdConnectConstants.ResponseTypes.Token, types);
        }

        [Fact]
        public async Task InvokeConfigurationEndpointAsync_DefaultScopesAreCorrectlyReturned() {
            // Arrange
            var server = CreateAuthorizationServer();

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.GetAsync(ConfigurationEndpoint);
            var scopes = response[OpenIdConnectConstants.Metadata.ScopesSupported].Values<string>();

            // Assert
            Assert.Contains(OpenIdConnectConstants.Scopes.OpenId, scopes);
        }

        [Fact]
        public async Task InvokeConfigurationEndpointAsync_DefaultSubjectTypesAreCorrectlyReturned() {
            // Arrange
            var server = CreateAuthorizationServer();

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.GetAsync(ConfigurationEndpoint);
            var types = response[OpenIdConnectConstants.Metadata.SubjectTypesSupported].Values<string>();

            // Assert
            Assert.Contains(OpenIdConnectConstants.SubjectTypes.Public, types);
        }

        [Theory]
        [InlineData(OpenIdConnectConstants.Algorithms.RsaSha256, "http://www.w3.org/2001/04/xmlenc#sha256")]
        [InlineData(OpenIdConnectConstants.Algorithms.RsaSha384, "http://www.w3.org/2001/04/xmlenc#sha384")]
        [InlineData(OpenIdConnectConstants.Algorithms.RsaSha512, "http://www.w3.org/2001/04/xmlenc#sha512")]
        public async Task InvokeConfigurationEndpointAsync_SigningAlgorithmsAreCorrectlyReturned(string algorithm, string digest) {
            // Arrange
            var parameters = new RSAParameters {
                D = Convert.FromBase64String("Uj6NrYBnyddhlJefYEP2nleCntAKlWyIttJC4cJnNxNN+OT2fQXhpTXRwW4R5YIS3HDqK/Fg2yoYm+OTVntAAgRFKveRx/WKwFo6UpnJc5u3lElhFa7IfosO9qXjErpX9ruAVqipekDLwQ++KmVVdgH4PK/o//nEx5zklGCdlEJURZYJPs9/7g1cx3UwvPp8jM7LgZL5OZRNyI3Jz4efrwiI2/vd8P28lAbpv/Ao4NwUDq/WKEnZ8JYSjLEKnZCfbX1ZEwf0Ic48jEKHmi1WEwpru1fMPoYfakrsY/VEfatPiDs8a5HABP/KaXcM4AZsr7HbzqAaNycV2xgdZimGcQ=="),
                DP = Convert.FromBase64String("hi1e+0eQ/iYrfT4zpZVbx3dyfA7Ch/aujMt6nGMF+1LGaut86vDHM2JI0Gc2BKc+uPEu2bNAorhSmuSyGpfGYl0MYFQoVF/jyiGpzYPmhYpL5yLuN9jWAqNwjfstuRDLU9zTEfZnr3OSN85rZcgT7NUxlY8im1Y2TWYxGiEXw9E="),
                DQ = Convert.FromBase64String("laVNkWIbnSuGo7nAxyUSdL2sXU3GZWwItwzTG0IK/0woFjArtCxGgNXW+V+GhxT7iHGAVJJSBvJ65TXrUYuBmoWj2CsoUs2mzK8ax4zg3CXrU61esCsGUoS2owR4FXlhYPmoVnglGu89bH72eXKixZsuF7vKW19nG703BXYEaEU="),
                Exponent = Convert.FromBase64String("AQAB"),
                InverseQ = Convert.FromBase64String("dhzLDS4F5WYHX+vH4+uL3Ei/K5lxw2A/dBHGtbS2X54gm7vARl+FrptOFFwIjjmsLuTjttAq9K1EP/XZIq8bjW6dXJ/IytnobIPSFkclEeQlMi4/2VDMG5915J0DwnKO9M+B8F3JViUyMv0pvb+ub+HHDVFkIr7zooCmY25i77Q="),
                Modulus = Convert.FromBase64String("kXv7Pxf6mSf7mu6mPAOAoKAXl5kU7Q3h9zevC5i4Mm5bMk17XCh7ZvVxDzGA+1JmyxOX6sw3gMUl31FtIFlDhis8VnXKAPn8i1zrmebq+7QKzpE2GpoIpXjXbkPaHG/DbC67M1bux7/dE7lSUSifHRRLsbMUC2D4UahJ6miH2iPFNFyoa6CLtwosD8tIJKwmZ9r9zfqc9BrVGu24lZySjTSRttpLaTkgkBjxHmYhinKNEtj9wUfi1S1wPJUvf+roc6o+7jeBBV3EXJCsb6XCCXI7/e3umWp19odeRShXLQNQbNuuVC7yre4iidUDrWJ1jiaB06svUG+fVEi4FCMvEQ=="),
                P = Convert.FromBase64String("xQGczmp4qD7Sez/ZqgW+O4cciTHvSqJqJUSdDd2l1Pd/szQ8avvzorrbSWOIULyv6eJb32+HuyLgy6rTSJ6THFobAnUv4ZTR7EGK26AJmP/BhD+3G+n21+4fzfbAxpHihkCYmO8aEl8fm/r4qPVXmCzFoXDZLMNIxFsdEXiFRS0="),
                Q = Convert.FromBase64String("vQy5C++AzF+TRh6qwbKzOqt87ZHEHidIAh6ivRNewjzIgCWXpseVl7DimY1YdViOnw1VI7xY+EyiyTanq5caTqqB3KcDm2t40bJfrZuUcn/5puRIh1bKNDwIMLsuNCrjHmDlNbocqpYMOh0Pgw7ARNbqrnPjWsYGJPuMNFpax/U=")
            };

            var rsa = RSA.Create();
            rsa.ImportParameters(parameters);

            var credentials = new SigningCredentials(new RsaSecurityKey(rsa), algorithm, digest);

            var server = CreateAuthorizationServer(options => {
                options.SigningCredentials.Clear();
                options.SigningCredentials.Add(credentials);
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.GetAsync(ConfigurationEndpoint);
            var algorithms = response[OpenIdConnectConstants.Metadata.IdTokenSigningAlgValuesSupported].Values<string>();

            // Assert
            Assert.Contains(algorithm, algorithms);
        }

        [Fact]
        public async Task InvokeConfigurationEndpointAsync_DefaultCodeChallengeMethodsAreCorrectlyReturned() {
            // Arrange
            var server = CreateAuthorizationServer();

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.GetAsync(ConfigurationEndpoint);
            var methods = response[OpenIdConnectConstants.Metadata.CodeChallengeMethodsSupported].Values<string>();

            // Assert
            Assert.Contains(OpenIdConnectConstants.CodeChallengeMethods.Plain, methods);
            Assert.Contains(OpenIdConnectConstants.CodeChallengeMethods.Sha256, methods);
        }

        [Theory]
        [InlineData("custom_error", null, null)]
        [InlineData("custom_error", "custom_description", null)]
        [InlineData("custom_error", "custom_description", "custom_uri")]
        [InlineData(null, "custom_description", null)]
        [InlineData(null, "custom_description", "custom_uri")]
        [InlineData(null, null, "custom_uri")]
        [InlineData(null, null, null)]
        public async Task InvokeConfigurationEndpointAsync_HandleConfigurationRequest_AllowsRejectingRequest(string error, string description, string uri) {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnValidateConfigurationRequest = context => {
                    context.Validate();

                    return Task.FromResult(0);
                };

                options.Provider.OnHandleConfigurationRequest = context => {
                    context.Reject(error, description, uri);

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.GetAsync(ConfigurationEndpoint);

            // Assert
            Assert.Equal(error ?? OpenIdConnectConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal(description, response.ErrorDescription);
            Assert.Equal(uri, response.ErrorUri);
        }

        [Fact]
        public async Task InvokeConfigurationEndpointAsync_HandleConfigurationRequest_AllowsHandlingResponse() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnValidateConfigurationRequest = context => {
                    context.Validate();

                    return Task.FromResult(0);
                };

                options.Provider.OnHandleConfigurationRequest = context => {
                    context.HandleResponse();

                    context.OwinContext.Response.Headers["Content-Type"] = "application/json";

                    return context.OwinContext.Response.WriteAsync(JsonConvert.SerializeObject(new {
                        name = "Bob le Magnifique"
                    }));
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.GetAsync(ConfigurationEndpoint);

            // Assert
            Assert.Equal("Bob le Magnifique", (string) response["name"]);
        }

        [Fact]
        public async Task InvokeConfigurationEndpointAsync_HandleConfigurationRequest_AllowsSkippingToNextMiddleware() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnValidateConfigurationRequest = context => {
                    context.Validate();

                    return Task.FromResult(0);
                };

                options.Provider.OnHandleConfigurationRequest = context => {
                    context.SkipToNextMiddleware();

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.GetAsync(ConfigurationEndpoint);

            // Assert
            Assert.Equal("Bob le Magnifique", (string) response["name"]);
        }

        [Fact]
        public async Task SendConfigurationResponseAsync_ApplyConfigurationResponse_AllowsHandlingResponse() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnValidateConfigurationRequest = context => {
                    context.Validate();

                    return Task.FromResult(0);
                };

                options.Provider.OnApplyConfigurationResponse = context => {
                    context.HandleResponse();

                    context.OwinContext.Response.Headers["Content-Type"] = "application/json";

                    return context.OwinContext.Response.WriteAsync(JsonConvert.SerializeObject(new {
                        name = "Bob le Magnifique"
                    }));
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.GetAsync(ConfigurationEndpoint);

            // Assert
            Assert.Equal("Bob le Magnifique", (string) response["name"]);
        }

        [Fact]
        public async Task SendConfigurationResponseAsync_ApplyConfigurationResponse_ResponseContainsCustomParameters() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnApplyConfigurationResponse = context => {
                    context.Response["custom_parameter"] = "custom_value";

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.GetAsync(ConfigurationEndpoint);

            // Assert
            Assert.Equal("custom_value", (string) response["custom_parameter"]);
        }

        [Theory]
        [InlineData(nameof(Delete))]
        [InlineData(nameof(Head))]
        [InlineData(nameof(Options))]
        [InlineData(nameof(Post))]
        [InlineData(nameof(Put))]
        [InlineData(nameof(Trace))]
        public async Task InvokeCryptographyEndpointAsync_UnexpectedMethodReturnsAnError(string method) {
            // Arrange
            var server = CreateAuthorizationServer();

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.SendAsync(method, CryptographyEndpoint, new OpenIdConnectRequest());

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal("Invalid HTTP method: make sure to use GET.", response.ErrorDescription);
        }

        [Theory]
        [InlineData("custom_error", null, null)]
        [InlineData("custom_error", "custom_description", null)]
        [InlineData("custom_error", "custom_description", "custom_uri")]
        [InlineData(null, "custom_description", null)]
        [InlineData(null, "custom_description", "custom_uri")]
        [InlineData(null, null, "custom_uri")]
        [InlineData(null, null, null)]
        public async Task InvokeCryptographyEndpointAsync_ExtractCryptographyRequest_AllowsRejectingRequest(string error, string description, string uri) {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnExtractCryptographyRequest = context => {
                    context.Reject(error, description, uri);

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.GetAsync(CryptographyEndpoint);

            // Assert
            Assert.Equal(error ?? OpenIdConnectConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal(description, response.ErrorDescription);
            Assert.Equal(uri, response.ErrorUri);
        }

        [Fact]
        public async Task InvokeCryptographyEndpointAsync_ExtractCryptographyRequest_AllowsHandlingResponse() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnExtractCryptographyRequest = context => {
                    context.HandleResponse();

                    context.OwinContext.Response.Headers["Content-Type"] = "application/json";

                    return context.OwinContext.Response.WriteAsync(JsonConvert.SerializeObject(new {
                        name = "Bob le Bricoleur"
                    }));
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.GetAsync(CryptographyEndpoint);

            // Assert
            Assert.Equal("Bob le Bricoleur", (string) response["name"]);
        }

        [Fact]
        public async Task InvokeCryptographyEndpointAsync_ExtractCryptographyRequest_AllowsSkippingToNextMiddleware() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnExtractCryptographyRequest = context => {
                    context.SkipToNextMiddleware();

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.GetAsync(CryptographyEndpoint);

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
        public async Task InvokeCryptographyEndpointAsync_ValidateCryptographyRequest_AllowsRejectingRequest(string error, string description, string uri) {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnValidateCryptographyRequest = context => {
                    context.Reject(error, description, uri);

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.GetAsync(CryptographyEndpoint);

            // Assert
            Assert.Equal(error ?? OpenIdConnectConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal(description, response.ErrorDescription);
            Assert.Equal(uri, response.ErrorUri);
        }

        [Fact]
        public async Task InvokeCryptographyEndpointAsync_ValidateCryptographyRequest_AllowsHandlingResponse() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnValidateCryptographyRequest = context => {
                    context.HandleResponse();

                    context.OwinContext.Response.Headers["Content-Type"] = "application/json";

                    return context.OwinContext.Response.WriteAsync(JsonConvert.SerializeObject(new {
                        name = "Bob le Magnifique"
                    }));
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.GetAsync(CryptographyEndpoint);

            // Assert
            Assert.Equal("Bob le Magnifique", (string) response["name"]);
        }

        [Fact]
        public async Task InvokeCryptographyEndpointAsync_ValidateCryptographyRequest_AllowsSkippingToNextMiddleware() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnValidateCryptographyRequest = context => {
                    context.SkipToNextMiddleware();

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.GetAsync(CryptographyEndpoint);

            // Assert
            Assert.Equal("Bob le Magnifique", (string) response["name"]);
        }

        [Theory]
        [InlineData("http://www.w3.org/2001/04/xmldsig-more#hmac-sha256", "http://www.w3.org/2001/04/xmlenc#sha256")]
        [InlineData("http://www.w3.org/2001/04/xmldsig-more#hmac-sha384", "http://www.w3.org/2001/04/xmlenc#sha384")]
        [InlineData("http://www.w3.org/2001/04/xmldsig-more#hmac-sha512", "http://www.w3.org/2001/04/xmlenc#sha512")]
        public async Task InvokeCryptographyEndpointAsync_UnsupportedSecurityKeysAreIgnored(string algorithm, string digest) {
            // Arrange
            var key = Mock.Of<SecurityKey>(mock => !mock.IsSupportedAlgorithm(algorithm));

            var server = CreateAuthorizationServer(options => {
                options.SigningCredentials.Clear();
                options.SigningCredentials.Add(new SigningCredentials(key, algorithm, algorithm));
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.GetAsync(CryptographyEndpoint);

            // Assert
            Assert.Null(response[OpenIdConnectConstants.Parameters.Keys]);
        }

        [Fact]
        public async Task InvokeCryptographyEndpointAsync_RsaSecurityKeysAreCorrectlyExposed() {
            // Arrange
            var parameters = new RSAParameters {
                D = Convert.FromBase64String("Uj6NrYBnyddhlJefYEP2nleCntAKlWyIttJC4cJnNxNN+OT2fQXhpTXRwW4R5YIS3HDqK/Fg2yoYm+OTVntAAgRFKveRx/WKwFo6UpnJc5u3lElhFa7IfosO9qXjErpX9ruAVqipekDLwQ++KmVVdgH4PK/o//nEx5zklGCdlEJURZYJPs9/7g1cx3UwvPp8jM7LgZL5OZRNyI3Jz4efrwiI2/vd8P28lAbpv/Ao4NwUDq/WKEnZ8JYSjLEKnZCfbX1ZEwf0Ic48jEKHmi1WEwpru1fMPoYfakrsY/VEfatPiDs8a5HABP/KaXcM4AZsr7HbzqAaNycV2xgdZimGcQ=="),
                DP = Convert.FromBase64String("hi1e+0eQ/iYrfT4zpZVbx3dyfA7Ch/aujMt6nGMF+1LGaut86vDHM2JI0Gc2BKc+uPEu2bNAorhSmuSyGpfGYl0MYFQoVF/jyiGpzYPmhYpL5yLuN9jWAqNwjfstuRDLU9zTEfZnr3OSN85rZcgT7NUxlY8im1Y2TWYxGiEXw9E="),
                DQ = Convert.FromBase64String("laVNkWIbnSuGo7nAxyUSdL2sXU3GZWwItwzTG0IK/0woFjArtCxGgNXW+V+GhxT7iHGAVJJSBvJ65TXrUYuBmoWj2CsoUs2mzK8ax4zg3CXrU61esCsGUoS2owR4FXlhYPmoVnglGu89bH72eXKixZsuF7vKW19nG703BXYEaEU="),
                Exponent = Convert.FromBase64String("AQAB"),
                InverseQ = Convert.FromBase64String("dhzLDS4F5WYHX+vH4+uL3Ei/K5lxw2A/dBHGtbS2X54gm7vARl+FrptOFFwIjjmsLuTjttAq9K1EP/XZIq8bjW6dXJ/IytnobIPSFkclEeQlMi4/2VDMG5915J0DwnKO9M+B8F3JViUyMv0pvb+ub+HHDVFkIr7zooCmY25i77Q="),
                Modulus = Convert.FromBase64String("kXv7Pxf6mSf7mu6mPAOAoKAXl5kU7Q3h9zevC5i4Mm5bMk17XCh7ZvVxDzGA+1JmyxOX6sw3gMUl31FtIFlDhis8VnXKAPn8i1zrmebq+7QKzpE2GpoIpXjXbkPaHG/DbC67M1bux7/dE7lSUSifHRRLsbMUC2D4UahJ6miH2iPFNFyoa6CLtwosD8tIJKwmZ9r9zfqc9BrVGu24lZySjTSRttpLaTkgkBjxHmYhinKNEtj9wUfi1S1wPJUvf+roc6o+7jeBBV3EXJCsb6XCCXI7/e3umWp19odeRShXLQNQbNuuVC7yre4iidUDrWJ1jiaB06svUG+fVEi4FCMvEQ=="),
                P = Convert.FromBase64String("xQGczmp4qD7Sez/ZqgW+O4cciTHvSqJqJUSdDd2l1Pd/szQ8avvzorrbSWOIULyv6eJb32+HuyLgy6rTSJ6THFobAnUv4ZTR7EGK26AJmP/BhD+3G+n21+4fzfbAxpHihkCYmO8aEl8fm/r4qPVXmCzFoXDZLMNIxFsdEXiFRS0="),
                Q = Convert.FromBase64String("vQy5C++AzF+TRh6qwbKzOqt87ZHEHidIAh6ivRNewjzIgCWXpseVl7DimY1YdViOnw1VI7xY+EyiyTanq5caTqqB3KcDm2t40bJfrZuUcn/5puRIh1bKNDwIMLsuNCrjHmDlNbocqpYMOh0Pgw7ARNbqrnPjWsYGJPuMNFpax/U=")
            };

            var rsa = RSA.Create();
            rsa.ImportParameters(parameters);

            var server = CreateAuthorizationServer(options => {
                options.SigningCredentials.Clear();
                options.SigningCredentials.AddKey(new RsaSecurityKey(rsa));
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.GetAsync(CryptographyEndpoint);
            var key = response[OpenIdConnectConstants.Parameters.Keys].First;

            // Assert
            Assert.Equal(parameters.Exponent, Base64UrlEncoder.DecodeBytes((string) key[JsonWebKeyParameterNames.E]));
            Assert.Equal(parameters.Modulus, Base64UrlEncoder.DecodeBytes((string) key[JsonWebKeyParameterNames.N]));
        }

        [Fact]
        public async Task InvokeCryptographyEndpointAsync_X509CertificatesAreCorrectlyExposed() {
            // Arrange
            var server = CreateAuthorizationServer();

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.GetAsync(CryptographyEndpoint);
            var key = response[OpenIdConnectConstants.Parameters.Keys].First;

            // Assert
            Assert.Equal("BSxeQhXNDB4VBeCOavOtvvv9eCI", (string) key[JsonWebKeyParameterNames.X5t]);
            Assert.Equal("MIIDPjCCAiqgAwIBAgIQlLEp+P+WKYtEAemhSKSUTTAJBgUrDgMCHQUAMC0xKzApBgNVBAMTIk93aW4uU2VjdXJpdHkuT3BlbklkQ29ubmVjdC5TZXJ2ZXIwHhcNOTkxMjMxMjIwMDAwWhcNNDkxMjMxMjIwMDAwWjAtMSswKQYDVQQDEyJPd2luLlNlY3VyaXR5Lk9wZW5JZENvbm5lY3QuU2VydmVyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwD/4uMNSIu+JlPRrtFR8Tm2LAwSOmglvJai6edFrdvDvk6xWzxYkMoIt4v13lFiIAUfI1vyZ1M0hWQfrifyweuzZu06DyWTUZkp9ervhTxK27HFN7XTuaRxHaXLR4KnhA+Nk8bBXN895OZh9g9Hf5+zsHpe17zgikwcyZtF+9OEG16oz7lKRgXGCIeeVZuSZ5Qf4yePwKMZqsx+lTOiZJ3JMs+gytvIpdZ1NWzcMX0XTcVTgvnBeU0O3NR6DQ41+SrGsojk11bd6kP6mVmDkA0K9kc2eh7q1wyJOeTNuCKRqLthwJ5m46/KRsxgY7ND6qHc1L60SqsFlYCJNEy7EdwIDAQABo2IwYDBeBgNVHQEEVzBVgBDQX+HKPiztLNvT3jQeBXqToS8wLTErMCkGA1UEAxMiT3dpbi5TZWN1cml0eS5PcGVuSWRDb25uZWN0LlNlcnZlcoIQlLEp+P+WKYtEAemhSKSUTTAJBgUrDgMCHQUAA4IBAQCxbCF5thB+ypGpudLAjv+l3M2VhNITJeR9j7jMlCSMVHvW7iMOL5W++zKvHMMAWuITLgPXTZ4ktsjeVQxWdnS2IcU7SwB9SeLbOMk4lLizoUevkiNaf6v+Hskm5LiH6+k8Zsl0INHyIjF9XlALTh91EqQ820cotDXaQIhHabQy892+dBmGWhSE1kP56IvOPzlLdSTkrcfcOu9gzwPVfuTDWH8Hrmo3FXz/fADmE7ea+yE1ZBeKhaN8kaFTs5zrprJ1BnmegnrjDY3RFgqcTTetahv0VBS0/jHSTIsAXflEPGW7LbHimzcgMytFU4fFtPVbek5eunakhu/JdENbbVmT", (string) key[JsonWebKeyParameterNames.X5c].First);
        }

        [Theory]
        [InlineData("custom_error", null, null)]
        [InlineData("custom_error", "custom_description", null)]
        [InlineData("custom_error", "custom_description", "custom_uri")]
        [InlineData(null, "custom_description", null)]
        [InlineData(null, "custom_description", "custom_uri")]
        [InlineData(null, null, "custom_uri")]
        [InlineData(null, null, null)]
        public async Task InvokeCryptographyEndpointAsync_HandleCryptographyRequest_AllowsRejectingRequest(string error, string description, string uri) {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnValidateCryptographyRequest = context => {
                    context.Validate();

                    return Task.FromResult(0);
                };

                options.Provider.OnHandleCryptographyRequest = context => {
                    context.Reject(error, description, uri);

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.GetAsync(CryptographyEndpoint);

            // Assert
            Assert.Equal(error ?? OpenIdConnectConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal(description, response.ErrorDescription);
            Assert.Equal(uri, response.ErrorUri);
        }

        [Fact]
        public async Task InvokeCryptographyEndpointAsync_HandleCryptographyRequest_AllowsHandlingResponse() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnValidateCryptographyRequest = context => {
                    context.Validate();

                    return Task.FromResult(0);
                };

                options.Provider.OnHandleCryptographyRequest = context => {
                    context.HandleResponse();

                    context.OwinContext.Response.Headers["Content-Type"] = "application/json";

                    return context.OwinContext.Response.WriteAsync(JsonConvert.SerializeObject(new {
                        name = "Bob le Magnifique"
                    }));
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.GetAsync(CryptographyEndpoint);

            // Assert
            Assert.Equal("Bob le Magnifique", (string) response["name"]);
        }

        [Fact]
        public async Task InvokeCryptographyEndpointAsync_HandleCryptographyRequest_AllowsSkippingToNextMiddleware() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnValidateCryptographyRequest = context => {
                    context.Validate();

                    return Task.FromResult(0);
                };

                options.Provider.OnHandleCryptographyRequest = context => {
                    context.SkipToNextMiddleware();

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.GetAsync(CryptographyEndpoint);

            // Assert
            Assert.Equal("Bob le Magnifique", (string) response["name"]);
        }

        [Fact]
        public async Task SendCryptographyResponseAsync_ApplyCryptographyResponse_AllowsHandlingResponse() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnValidateCryptographyRequest = context => {
                    context.Validate();

                    return Task.FromResult(0);
                };

                options.Provider.OnApplyCryptographyResponse = context => {
                    context.HandleResponse();

                    context.OwinContext.Response.Headers["Content-Type"] = "application/json";

                    return context.OwinContext.Response.WriteAsync(JsonConvert.SerializeObject(new {
                        name = "Bob le Magnifique"
                    }));
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.GetAsync(CryptographyEndpoint);

            // Assert
            Assert.Equal("Bob le Magnifique", (string) response["name"]);
        }

        [Fact]
        public async Task SendCryptographyResponseAsync_ApplyCryptographyResponse_ResponseContainsCustomParameters() {
            // Arrange
            var server = CreateAuthorizationServer(options => {
                options.Provider.OnApplyCryptographyResponse = context => {
                    context.Response["custom_parameter"] = "custom_value";

                    return Task.FromResult(0);
                };
            });

            var client = new OpenIdConnectClient(server.HttpClient);

            // Act
            var response = await client.GetAsync(CryptographyEndpoint);

            // Assert
            Assert.Equal("custom_value", (string) response["custom_parameter"]);
        }
    }
}
