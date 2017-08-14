/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using AspNet.Security.OpenIdConnect.Primitives;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Builder.Internal;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Moq;
using Xunit;

namespace AspNet.Security.OpenIdConnect.Server.Tests
{
    public class OpenIdConnectServerExtensionsTests
    {
        [Fact]
        public void UseOpenIdConnectServer_ThrowsAnExceptionForNullBuilder()
        {
            // Arrange
            var builder = (IApplicationBuilder) null;

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(delegate
            {
                builder.UseOpenIdConnectServer(new OpenIdConnectServerOptions());
            });

            Assert.Equal("app", exception.ParamName);
        }

        [Fact]
        public void UseOpenIdConnectServer_ThrowsAnExceptionForNullConfiguration()
        {
            // Arrange
            var services = new ServiceCollection();
            var builder = new ApplicationBuilder(services.BuildServiceProvider());

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(delegate
            {
                builder.UseOpenIdConnectServer(configuration: null);
            });

            Assert.Equal("configuration", exception.ParamName);
        }

        [Fact]
        public void UseOpenIdConnectServer_ThrowsAnExceptionForNullOptions()
        {
            // Arrange
            var services = new ServiceCollection();
            var builder = new ApplicationBuilder(services.BuildServiceProvider());

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(delegate
            {
                builder.UseOpenIdConnectServer(options: null);
            });

            Assert.Equal("options", exception.ParamName);
        }

        [Fact]
        public void UseOpenIdConnectServer_MiddlewareIsRegistered()
        {
            // Arrange
            var builder = new Mock<IApplicationBuilder>();

            // Act
            builder.Object.UseOpenIdConnectServer(new OpenIdConnectServerOptions());

            // Assert
            builder.Verify(mock => mock.Use(It.IsAny<Func<RequestDelegate, RequestDelegate>>()), Times.Once());
        }

        [Fact]
        public void AddCertificate_ThrowsAnExceptionForNullCredentials()
        {
            // Arrange
            var credentials = (IList<SigningCredentials>) null;

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(delegate
            {
                credentials.AddCertificate(certificate: null);
            });

            Assert.Equal("credentials", exception.ParamName);
        }

        [Fact]
        public void AddCertificate_ThrowsAnExceptionForNullCertificate()
        {
            // Arrange
            var credentials = new List<SigningCredentials>();

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(delegate
            {
                credentials.AddCertificate(certificate: null);
            });

            Assert.Equal("certificate", exception.ParamName);
        }

        [Fact]
        public void AddCertificate_ThrowsAnExceptionForNullAssembly()
        {
            // Arrange
            var credentials = new List<SigningCredentials>();

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(delegate
            {
                credentials.AddCertificate(assembly: null, resource: null, password: null);
            });

            Assert.Equal("assembly", exception.ParamName);
        }

        [Theory]
        [InlineData("")]
        [InlineData(null)]
        public void AddCertificate_ThrowsAnExceptionForNullOrEmptyResource(string resource)
        {
            // Arrange
            var credentials = new List<SigningCredentials>();
            var assembly = typeof(OpenIdConnectServerMiddlewareTests).GetTypeInfo().Assembly;

            // Act and assert
            var exception = Assert.Throws<ArgumentException>(delegate
            {
                credentials.AddCertificate(assembly, resource, password: null);
            });

            Assert.Equal("resource", exception.ParamName);
            Assert.StartsWith("The resource cannot be null or empty.", exception.Message);
        }

        [Theory]
        [InlineData("")]
        [InlineData(null)]
        public void AddCertificate_ThrowsAnExceptionForNullOrEmptyPassword(string password)
        {
            // Arrange
            var credentials = new List<SigningCredentials>();
            var assembly = typeof(OpenIdConnectServerMiddlewareTests).GetTypeInfo().Assembly;
            var resource = "AspNet.Security.OpenIdConnect.Server.Tests.Certificate.cer";

            // Act and assert
            var exception = Assert.Throws<ArgumentException>(delegate
            {
                credentials.AddCertificate(assembly, resource, password);
            });

            Assert.Equal("password", exception.ParamName);
            Assert.StartsWith("The password cannot be null or empty.", exception.Message);
        }

        [Theory]
        [InlineData("")]
        [InlineData(null)]
        public void AddCertificate_ThrowsAnExceptionForNullOrEmptyThumbprint(string thumbprint)
        {
            // Arrange
            var credentials = new List<SigningCredentials>();

            // Act and assert
            var exception = Assert.Throws<ArgumentException>(delegate
            {
                credentials.AddCertificate(thumbprint);
            });

            Assert.Equal("thumbprint", exception.ParamName);
            Assert.StartsWith("The thumbprint cannot be null or empty.", exception.Message);
        }

        [Fact]
        public void AddCertificate_ThrowsAnExceptionForInvalidResource()
        {
            // Arrange
            var credentials = new List<SigningCredentials>();
            var assembly = typeof(OpenIdConnectServerMiddlewareTests).GetTypeInfo().Assembly;

            // Act and assert
            var exception = Assert.Throws<InvalidOperationException>(delegate
            {
                credentials.AddCertificate(assembly, "resource", "password");
            });

            Assert.Equal("The certificate was not found in the specified assembly.", exception.Message);
        }

        [Fact]
        public void AddCertificate_ThrowsAnExceptionForInvalidThumbprint()
        {
            // Arrange
            var credentials = new List<SigningCredentials>();

            // Act and assert
            var exception = Assert.Throws<InvalidOperationException>(delegate
            {
                credentials.AddCertificate("thumbprint", StoreName.Root, StoreLocation.LocalMachine);
            });

            Assert.Equal("The certificate corresponding to the specified thumbprint was not found.", exception.Message);
        }

        [Fact]
        public void AddCertificate_ThrowsAnExceptionForCertificateWithNoPrivateKey()
        {
            // Arrange
            var credentials = new List<SigningCredentials>();
            var assembly = typeof(OpenIdConnectServerMiddlewareTests).GetTypeInfo().Assembly;
            var resource = "AspNet.Security.OpenIdConnect.Server.Tests.Certificate.cer";

            X509Certificate2 certificate;
            using (var buffer = new MemoryStream())
            using (var stream = assembly.GetManifestResourceStream(resource))
            {
                stream.CopyTo(buffer);

                certificate = new X509Certificate2(buffer.ToArray());
            }

            // Act and assert
            var exception = Assert.Throws<InvalidOperationException>(delegate
            {
                credentials.AddCertificate(certificate);
            });

            Assert.Equal("The specified certificate doesn't contain the required private key.", exception.Message);
        }

        [Fact]
        public void AddCertificate_RegistersSigningCredentials()
        {
            // Arrange
            var credentials = new List<SigningCredentials>();

            // Act
            credentials.AddCertificate(
                assembly: typeof(OpenIdConnectServerMiddlewareTests).GetTypeInfo().Assembly,
                resource: "AspNet.Security.OpenIdConnect.Server.Tests.Certificate.pfx",
                password: "Owin.Security.OpenIdConnect.Server");

            // Assert
            Assert.Single(credentials);
            Assert.Equal(SecurityAlgorithms.RsaSha256Signature, credentials[0].Algorithm);
            Assert.NotNull(credentials[0].Kid);
        }

        [Fact]
        public void AddEphemeralKey_ThrowsAnExceptionForNullCredentials()
        {
            // Arrange
            var credentials = (IList<SigningCredentials>) null;

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(delegate
            {
                credentials.AddEphemeralKey(SecurityAlgorithms.RsaSha256Signature);
            });

            Assert.Equal("credentials", exception.ParamName);
        }

        [Theory]
        [InlineData("")]
        [InlineData(null)]
        public void AddEphemeralKey_ThrowsAnExceptionForNullOrEmptyAlgorithm(string algorithm)
        {
            // Arrange
            var credentials = new List<SigningCredentials>();

            // Act and assert
            var exception = Assert.Throws<ArgumentException>(delegate
            {
                credentials.AddEphemeralKey(algorithm);
            });

            Assert.Equal("algorithm", exception.ParamName);
            Assert.StartsWith("The algorithm cannot be null or empty.", exception.Message);
        }

#if !SUPPORTS_ECDSA
        [Theory]
        [InlineData(SecurityAlgorithms.EcdsaSha256Signature)]
        [InlineData(SecurityAlgorithms.EcdsaSha384Signature)]
        [InlineData(SecurityAlgorithms.EcdsaSha512Signature)]
        public void AddEphemeralKey_ThrowsAnExceptionForEcdsaAlgorithmsOnUnsupportedPlatforms(string algorithm)
        {
            // Arrange
            var credentials = new List<SigningCredentials>();

            // Act and assert
            var exception = Assert.Throws<PlatformNotSupportedException>(delegate
            {
                credentials.AddEphemeralKey(algorithm);
            });

            Assert.Equal("ECDSA signing keys are not supported on this platform.", exception.Message);
        }
#endif

        [Theory]
        [InlineData(SecurityAlgorithms.HmacSha256Signature)]
        [InlineData(SecurityAlgorithms.HmacSha384Signature)]
        [InlineData(SecurityAlgorithms.HmacSha512Signature)]
        public void AddEphemeralKey_ThrowsAnExceptionForUnsupportedAlgorithms(string algorithm)
        {
            // Arrange
            var credentials = new List<SigningCredentials>();

            // Act and assert
            var exception = Assert.Throws<InvalidOperationException>(delegate
            {
                credentials.AddEphemeralKey(algorithm);
            });

            Assert.Equal("The specified algorithm is not supported.", exception.Message);
        }

        [Theory]
        [InlineData(SecurityAlgorithms.RsaSha256Signature)]
        [InlineData(SecurityAlgorithms.RsaSha384Signature)]
        [InlineData(SecurityAlgorithms.RsaSha512Signature)]
#if SUPPORTS_ECDSA
        [InlineData(SecurityAlgorithms.EcdsaSha256Signature)]
        [InlineData(SecurityAlgorithms.EcdsaSha384Signature)]
        [InlineData(SecurityAlgorithms.EcdsaSha512Signature)]
#endif
        public void AddEphemeralKey_RegistersSigningCredentials(string algorithm)
        {
            // Arrange
            var credentials = new List<SigningCredentials>();

            // Act
            credentials.AddEphemeralKey(algorithm);

            // Assert
            Assert.Single(credentials);
            Assert.Equal(algorithm, credentials[0].Algorithm);
            Assert.NotNull(credentials[0].Kid);
        }

        [Fact]
        public void AddEphemeralKey_UsesRsaSha256ByDefault()
        {
            // Arrange
            var credentials = new List<SigningCredentials>();

            // Act
            credentials.AddEphemeralKey();

            // Assert
            Assert.Single(credentials);
            Assert.Equal(SecurityAlgorithms.RsaSha256Signature, credentials[0].Algorithm);
            Assert.NotNull(credentials[0].Kid);
        }

        [Fact]
        public void AddKey_ThrowsAnExceptionForNullCredentials()
        {
            // Arrange
            var credentials = (IList<SigningCredentials>) null;

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(delegate
            {
                credentials.AddKey(null);
            });

            Assert.Equal("credentials", exception.ParamName);
        }

        [Fact]
        public void AddKey_ThrowsAnExceptionForNullKey()
        {
            // Arrange
            var credentials = new List<SigningCredentials>();

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(delegate
            {
                credentials.AddKey(null);
            });

            Assert.Equal("key", exception.ParamName);
        }

        [Fact]
        public void AddKey_ThrowsAnExceptionForNonPrivateKey()
        {
            // Arrange
            var credentials = new List<SigningCredentials>();
            var key = Mock.Of<AsymmetricSecurityKey>(mock => !mock.HasPrivateKey);

            // Act and assert
            var exception = Assert.Throws<InvalidOperationException>(delegate
            {
                credentials.AddKey(key);
            });

            Assert.Equal("The asymmetric signing key doesn't contain the required private key.", exception.Message);
        }

#if !SUPPORTS_ECDSA
        [Fact]
        public void AddKey_ThrowsAnExceptionForEcdsaKeyOnUnsupportedPlatforms()
        {
            // Arrange
            var credentials = new List<SigningCredentials>();
            var key = new ECDsaSecurityKey(Mock.Of<ECDsa>());

            // Act and assert
            var exception = Assert.Throws<PlatformNotSupportedException>(delegate
            {
                credentials.AddKey(key);
            });

            Assert.Equal("ECDSA signing keys are not supported on this platform.", exception.Message);
        }
#endif

        [Fact]
        public void AddKey_ThrowsAnExceptionForUnsupportedAlgorithm()
        {
            // Arrange
            var credentials = new List<SigningCredentials>();
            var key = Mock.Of<SecurityKey>();

            // Act and assert
            var exception = Assert.Throws<InvalidOperationException>(delegate
            {
                credentials.AddKey(key);
            });

            Assert.Equal("A signature algorithm cannot be automatically inferred from the signing key. " +
                         "Consider using 'options.SigningCredentials.Add(SigningCredentials)' instead.", exception.Message);
        }

        [Theory]
        [InlineData(SecurityAlgorithms.HmacSha256Signature)]
        [InlineData(SecurityAlgorithms.RsaSha256Signature)]
#if SUPPORTS_ECDSA
        [InlineData(SecurityAlgorithms.EcdsaSha256Signature)]
        [InlineData(SecurityAlgorithms.EcdsaSha384Signature)]
        [InlineData(SecurityAlgorithms.EcdsaSha512Signature)]
#endif
        public void AddKey_RegistersSigningCredentials(string algorithm)
        {
            // Arrange
            var credentials = new List<SigningCredentials>();
            var factory = Mock.Of<CryptoProviderFactory>(mock => mock.IsSupportedAlgorithm(algorithm, It.IsAny<SecurityKey>()));
            var key = Mock.Of<SecurityKey>(mock => mock.CryptoProviderFactory == factory);

            // Act
            credentials.AddKey(key);

            // Assert
            Assert.Single(credentials);
            Assert.Equal(algorithm, credentials[0].Algorithm);
        }

        [Fact]
        public void GetOpenIdConnectRequest_ThrowsAnExceptionForNullContext()
        {
            // Arrange
            var context = (HttpContext) null;

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(delegate
            {
                context.GetOpenIdConnectRequest();
            });

            Assert.Equal("context", exception.ParamName);
        }

        [Fact]
        public void GetOpenIdConnectRequest_ReturnsNullForMissingFeature()
        {
            // Arrange
            var context = new DefaultHttpContext();

            // Act and assert
            Assert.Null(context.GetOpenIdConnectRequest());
        }

        [Fact]
        public void GetOpenIdConnectRequest_ReturnsExpectedRequest()
        {
            // Arrange
            var request = new OpenIdConnectRequest();

            var features = new FeatureCollection();
            features.Set(new OpenIdConnectServerFeature
            {
                Request = request
            });

            var context = new DefaultHttpContext(features);

            // Act and assert
            Assert.Same(request, context.GetOpenIdConnectRequest());
        }

        [Fact]
        public void GetOpenIdConnectResponse_ThrowsAnExceptionForNullContext()
        {
            // Arrange
            var context = (HttpContext) null;

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(delegate
            {
                context.GetOpenIdConnectResponse();
            });

            Assert.Equal("context", exception.ParamName);
        }

        [Fact]
        public void GetOpenIdConnectResponse_ReturnsNullForMissingFeature()
        {
            // Arrange
            var context = new DefaultHttpContext();

            // Act and assert
            Assert.Null(context.GetOpenIdConnectResponse());
        }

        [Fact]
        public void GetOpenIdConnectResponse_ReturnsExpectedResponse()
        {
            // Arrange
            var response = new OpenIdConnectResponse();

            var features = new FeatureCollection();
            features.Set(new OpenIdConnectServerFeature
            {
                Response = response
            });

            var context = new DefaultHttpContext(features);

            // Act and assert
            Assert.Same(response, context.GetOpenIdConnectResponse());
        }

        [Fact]
        public void SetOpenIdConnectRequest_ThrowsAnExceptionForNullContext()
        {
            // Arrange
            var context = (HttpContext) null;

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(delegate
            {
                context.SetOpenIdConnectRequest(request: null);
            });

            Assert.Equal("context", exception.ParamName);
        }

        [Fact]
        public void SetOpenIdConnectRequest_DoesNotThrowAnExceptionForNullRequest()
        {
            // Arrange
            var feature = new OpenIdConnectServerFeature();

            var features = new FeatureCollection();
            features.Set(feature);

            var context = new DefaultHttpContext(features);

            // Act
            context.SetOpenIdConnectRequest(request: null);

            // Assert
            Assert.Null(feature.Request);
        }

        [Fact]
        public void SetOpenIdConnectRequest_AttachesRequest()
        {
            // Arrange
            var request = new OpenIdConnectRequest();
            var feature = new OpenIdConnectServerFeature();

            var features = new FeatureCollection();
            features.Set(feature);

            var context = new DefaultHttpContext(features);

            // Act
            context.SetOpenIdConnectRequest(request);

            // Assert
            Assert.Same(request, feature.Request);
        }

        [Fact]
        public void SetOpenIdConnectResponse_ThrowsAnExceptionForNullContext()
        {
            // Arrange
            var context = (HttpContext) null;

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(delegate
            {
                context.SetOpenIdConnectResponse(response: null);
            });

            Assert.Equal("context", exception.ParamName);
        }

        [Fact]
        public void SetOpenIdConnectResponse_DoesNotThrowAnExceptionForNullResponse()
        {
            // Arrange
            var feature = new OpenIdConnectServerFeature();

            var features = new FeatureCollection();
            features.Set(feature);

            var context = new DefaultHttpContext(features);

            // Act
            context.SetOpenIdConnectResponse(response: null);

            // Assert
            Assert.Null(feature.Response);
        }

        [Fact]
        public void SetOpenIdConnectResponse_AttachesResponse()
        {
            // Arrange
            var response = new OpenIdConnectResponse();
            var feature = new OpenIdConnectServerFeature();

            var features = new FeatureCollection();
            features.Set(feature);

            var context = new DefaultHttpContext(features);

            // Act
            context.SetOpenIdConnectResponse(response);

            // Assert
            Assert.Same(response, feature.Response);
        }
    }
}