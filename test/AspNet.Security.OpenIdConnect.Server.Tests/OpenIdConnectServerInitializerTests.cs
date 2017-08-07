/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.IdentityModel.Tokens.Jwt;
using System.Reflection;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Client;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Xunit;

namespace AspNet.Security.OpenIdConnect.Server.Tests
{
    public partial class OpenIdConnectServerInitializerTests
    {
        [Fact]
        public async Task PostConfigure_MissingProviderThrowsAnException()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Provider = null;
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act and assert
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
            {
                return client.GetAsync("/");
            });

            Assert.Equal("The authorization provider registered in the options cannot be null.", exception.Message);
        }

        [Fact]
        public async Task PostConfigure_InvalidProviderTypeThrowsAnException()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.ProviderType = typeof(object);
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act and assert
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
            {
                return client.GetAsync("/");
            });

            Assert.Equal($"The authorization provider must derive from 'OpenIdConnectServerProvider'.", exception.Message);
        }

        [Fact]
        public async Task PostConfigure_RelativeIssuerThrowsAnException()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Issuer = new Uri("/path", UriKind.Relative);
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act and assert
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
            {
                return client.GetAsync("/");
            });

            Assert.Equal("The issuer registered in the options must be a valid absolute URI.", exception.Message);
        }

        [Theory]
        [InlineData("http://www.fabrikam.com/path?param=value")]
        [InlineData("http://www.fabrikam.com/path#param=value")]
        public async Task PostConfigure_InvalidIssuerThrowsAnException(string issuer)
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.Issuer = new Uri(issuer);
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act and assert
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
            {
                return client.GetAsync("/");
            });

            Assert.Equal("The issuer registered in the options must contain " +
                         "no query and no fragment parts.", exception.Message);
        }

        [Fact]
        public async Task PostConfigure_NonHttpsIssuerThrowsAnExceptionWhenAllowInsecureHttpIsNotEnabled()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.AllowInsecureHttp = false;
                options.Issuer = new Uri("http://www.fabrikam.com/");
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act and assert
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
            {
                return client.GetAsync("/");
            });

            Assert.Equal("The issuer registered in the options must be a HTTPS URI when " +
                         "AllowInsecureHttp is not set to true.", exception.Message);
        }

        [Fact]
        public async Task PostConfigure_MissingSigningCredentialsThrowAnException()
        {
            // Arrange
            var server = CreateAuthorizationServer(options =>
            {
                options.AccessTokenHandler = new JwtSecurityTokenHandler();
                options.SigningCredentials.Clear();
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act and assert
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
            {
                return client.GetAsync("/");
            });

            Assert.Equal(
                "At least one signing key must be registered when using JWT as the access token format. " +
                "Consider registering a X.509 certificate using 'options.SigningCredentials.AddCertificate()' " +
                "or 'options.SigningCredentials.AddDevelopmentCertificate()' or call " +
                "'options.SigningCredentials.AddEphemeralKey()' to use an ephemeral key.", exception.Message);
        }

        [Fact]
        public async Task PostConfigure_InvalidDefaultSchemeThrowsAnException()
        {
            // Arrange
            var server = CreateAuthorizationServer(null, services =>
            {
                services.AddAuthentication(options =>
                {
                    options.DefaultScheme = OpenIdConnectServerDefaults.AuthenticationScheme;
                });
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act and assert
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
            {
                return client.GetAsync("/");
            });

            Assert.Equal("The OpenID Connect server handler cannot be used as the default scheme handler. " +
                         "Make sure that neither DefaultAuthenticateScheme, DefaultChallengeScheme, " +
                         "DefaultForbidScheme, DefaultSignInScheme, DefaultSignOutScheme nor DefaultScheme" +
                         "point to an instance of the OpenID Connect server handler.", exception.Message);
        }

        [Fact]
        public async Task PostConfigure_InvalidDefaultAuthenticationSchemeThrowsAnException()
        {
            // Arrange
            var server = CreateAuthorizationServer(null, services =>
            {
                services.AddAuthentication(options =>
                {
                    options.DefaultAuthenticateScheme = OpenIdConnectServerDefaults.AuthenticationScheme;
                });
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act and assert
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
            {
                return client.GetAsync("/");
            });

            Assert.Equal("The OpenID Connect server handler cannot be used as the default scheme handler. " +
                         "Make sure that neither DefaultAuthenticateScheme, DefaultChallengeScheme, " +
                         "DefaultForbidScheme, DefaultSignInScheme, DefaultSignOutScheme nor DefaultScheme" +
                         "point to an instance of the OpenID Connect server handler.", exception.Message);
        }

        [Fact]
        public async Task PostConfigure_InvalidDefaultChallengeSchemeThrowsAnException()
        {
            // Arrange
            var server = CreateAuthorizationServer(null, services =>
            {
                services.AddAuthentication(options =>
                {
                    options.DefaultChallengeScheme = OpenIdConnectServerDefaults.AuthenticationScheme;
                });
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act and assert
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
            {
                return client.GetAsync("/");
            });

            Assert.Equal("The OpenID Connect server handler cannot be used as the default scheme handler. " +
                         "Make sure that neither DefaultAuthenticateScheme, DefaultChallengeScheme, " +
                         "DefaultForbidScheme, DefaultSignInScheme, DefaultSignOutScheme nor DefaultScheme" +
                         "point to an instance of the OpenID Connect server handler.", exception.Message);
        }

        [Fact]
        public async Task PostConfigure_InvalidDefaultForbidSchemeThrowsAnException()
        {
            // Arrange
            var server = CreateAuthorizationServer(null, services =>
            {
                services.AddAuthentication(options =>
                {
                    options.DefaultForbidScheme = OpenIdConnectServerDefaults.AuthenticationScheme;
                });
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act and assert
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
            {
                return client.GetAsync("/");
            });

            Assert.Equal("The OpenID Connect server handler cannot be used as the default scheme handler. " +
                         "Make sure that neither DefaultAuthenticateScheme, DefaultChallengeScheme, " +
                         "DefaultForbidScheme, DefaultSignInScheme, DefaultSignOutScheme nor DefaultScheme" +
                         "point to an instance of the OpenID Connect server handler.", exception.Message);
        }

        [Fact]
        public async Task PostConfigure_InvalidDefaultSignInSchemeThrowsAnException()
        {
            // Arrange
            var server = CreateAuthorizationServer(null, services =>
            {
                services.AddAuthentication(options =>
                {
                    options.DefaultSignInScheme = OpenIdConnectServerDefaults.AuthenticationScheme;
                });
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act and assert
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
            {
                return client.GetAsync("/");
            });

            Assert.Equal("The OpenID Connect server handler cannot be used as the default scheme handler. " +
                         "Make sure that neither DefaultAuthenticateScheme, DefaultChallengeScheme, " +
                         "DefaultForbidScheme, DefaultSignInScheme, DefaultSignOutScheme nor DefaultScheme" +
                         "point to an instance of the OpenID Connect server handler.", exception.Message);
        }

        [Fact]
        public async Task PostConfigure_InvalidDefaultSignOutSchemeThrowsAnException()
        {
            // Arrange
            var server = CreateAuthorizationServer(null, services =>
            {
                services.AddAuthentication(options =>
                {
                    options.DefaultSignOutScheme = OpenIdConnectServerDefaults.AuthenticationScheme;
                });
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act and assert
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
            {
                return client.GetAsync("/");
            });

            Assert.Equal("The OpenID Connect server handler cannot be used as the default scheme handler. " +
                         "Make sure that neither DefaultAuthenticateScheme, DefaultChallengeScheme, " +
                         "DefaultForbidScheme, DefaultSignInScheme, DefaultSignOutScheme nor DefaultScheme" +
                         "point to an instance of the OpenID Connect server handler.", exception.Message);
        }

        private static TestServer CreateAuthorizationServer(
            Action<OpenIdConnectServerOptions> configuration = null,
            Action<IServiceCollection> registration = null)
        {
            var builder = new WebHostBuilder();

            builder.UseEnvironment("Testing");

            builder.ConfigureServices(services =>
            {
                services.AddAuthentication()
                    .AddOpenIdConnectServer(options =>
                    {
                        options.SigningCredentials.AddCertificate(
                            assembly: typeof(OpenIdConnectServerHandlerTests).GetTypeInfo().Assembly,
                            resource: "AspNet.Security.OpenIdConnect.Server.Tests.Certificate.pfx",
                            password: "Owin.Security.OpenIdConnect.Server");

                        // Note: overriding the default data protection provider is not necessary for the tests to pass,
                        // but is useful to ensure unnecessary keys are not persisted in testing environments, which also
                        // helps make the unit tests run faster, as no registry or disk access is required in this case.
                        options.DataProtectionProvider = new EphemeralDataProtectionProvider(new LoggerFactory());

                        // Run the configuration delegate
                        // registered by the unit tests.
                        configuration?.Invoke(options);
                    });

                registration?.Invoke(services);
            });

            builder.Configure(app =>
            {
                app.UseAuthentication();

                app.Run(context => context.ChallengeAsync(OpenIdConnectServerDefaults.AuthenticationScheme));
            });

            return new TestServer(builder);
        }
    }
}
