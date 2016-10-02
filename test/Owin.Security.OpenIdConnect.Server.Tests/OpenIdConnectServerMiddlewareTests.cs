using System;
using System.Reflection;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Owin.Testing;
using Xunit;

namespace Owin.Security.OpenIdConnect.Server.Tests {
    public class OpenIdConnectServerMiddlewareTests {
        [Fact]
        public void Constructor_MissingProviderThrowsAnException() {
            // Arrange, act, assert
            var exception = Assert.Throws<TargetInvocationException>(() => CreateAuthorizationServer(options => {
                options.Provider = null;
            }));

            Assert.IsType<ArgumentException>(exception.InnerException);
            Assert.Equal("options", ((ArgumentException) exception.InnerException).ParamName);
            Assert.StartsWith("The authorization provider registered in the options cannot be null.", exception.InnerException.Message);
        }

        [Fact]
        public void Constructor_MissingClockThrowsAnException() {
            // Arrange, act, assert
            var exception = Assert.Throws<TargetInvocationException>(() => CreateAuthorizationServer(options => {
                options.SystemClock = null;
            }));

            Assert.IsType<ArgumentException>(exception.InnerException);
            Assert.Equal("options", ((ArgumentException) exception.InnerException).ParamName);
            Assert.StartsWith("The system clock registered in the options cannot be null.", exception.InnerException.Message);
        }

        [Fact]
        public void Constructor_RelativeIssuerThrowsAnException() {
            // Arrange, act, assert
            var exception = Assert.Throws<TargetInvocationException>(() => CreateAuthorizationServer(options => {
                options.Issuer = new Uri("/path", UriKind.Relative);
            }));

            Assert.IsType<ArgumentException>(exception.InnerException);
            Assert.Equal("options", ((ArgumentException) exception.InnerException).ParamName);
            Assert.StartsWith("The issuer registered in the options must be a valid absolute URI.", exception.InnerException.Message);
        }

        [Theory]
        [InlineData("http://www.fabrikam.com/path?param=value")]
        [InlineData("http://www.fabrikam.com/path#param=value")]
        public void Constructor_InvalidIssuerThrowsAnException(string issuer) {
            // Arrange, act, assert
            var exception = Assert.Throws<TargetInvocationException>(() => CreateAuthorizationServer(options => {
                options.Issuer = new Uri(issuer);
            }));

            Assert.IsType<ArgumentException>(exception.InnerException);
            Assert.Equal("options", ((ArgumentException) exception.InnerException).ParamName);
            Assert.StartsWith("The issuer registered in the options must contain " +
                              "no query and no fragment parts.", exception.InnerException.Message);
        }

        [Fact]
        public void Constructor_NonHttpsIssuerThrowsAnExceptionWhenAllowInsecureHttpIsNotEnabled() {
            // Arrange, act, assert
            var exception = Assert.Throws<TargetInvocationException>(() => CreateAuthorizationServer(options => {
                options.AllowInsecureHttp = false;
                options.Issuer = new Uri("http://www.fabrikam.com/");
            }));

            Assert.IsType<ArgumentException>(exception.InnerException);
            Assert.Equal("options", ((ArgumentException) exception.InnerException).ParamName);
            Assert.StartsWith("The issuer registered in the options must be a HTTPS URI when " +
                              "AllowInsecureHttp is not set to true.", exception.InnerException.Message);
        }

        [Fact]
        public void Constructor_MissingSigningCredentialsThrowAnException() {
            // Arrange, act, assert
            var exception = Assert.Throws<TargetInvocationException>(() => CreateAuthorizationServer(options => {
                options.SigningCredentials.Clear();
            }));

            Assert.IsType<ArgumentException>(exception.InnerException);
            Assert.Equal("options", ((ArgumentException) exception.InnerException).ParamName);
            Assert.StartsWith("At least one signing key must be registered. Consider registering " +
                              "a X.509 certificate or call 'options.SigningCredentials.AddEphemeralKey()' " +
                              "to generate and register an ephemeral signing key.", exception.InnerException.Message);
        }

        private static TestServer CreateAuthorizationServer(Action<OpenIdConnectServerOptions> configuration = null) {
            return TestServer.Create(app => {
                app.UseOpenIdConnectServer(options => {
                    options.AllowInsecureHttp = true;

                    options.SigningCredentials.AddCertificate(
                        assembly: typeof(OpenIdConnectServerMiddlewareTests).GetTypeInfo().Assembly,
                        resource: "Owin.Security.OpenIdConnect.Server.Tests.Certificate.pfx",
                        password: "Owin.Security.OpenIdConnect.Server");

                    // Note: overriding the default data protection provider is not necessary for the tests to pass,
                    // but is useful to ensure unnecessary keys are not persisted in testing environments, which also
                    // helps make the unit tests run faster, as no registry or disk access is required in this case.
                    options.DataProtectionProvider = new EphemeralDataProtectionProvider();

                    // Run the configuration delegate
                    // registered by the unit tests.
                    configuration?.Invoke(options);
                });
            });
        }
    }
}