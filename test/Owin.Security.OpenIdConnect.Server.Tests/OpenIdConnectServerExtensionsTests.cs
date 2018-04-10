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
using Microsoft.IdentityModel.Tokens;
using Microsoft.Owin;
using Microsoft.Owin.Builder;
using Moq;
using Xunit;

namespace Owin.Security.OpenIdConnect.Server.Tests
{
    public class OpenIdConnectServerExtensionsTests
    {
        [Fact]
        public void UseOpenIdConnectServer_ThrowsAnExceptionForNullBuilder()
        {
            // Arrange
            var builder = (IAppBuilder) null;

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
            var builder = new AppBuilder();

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
            var builder = new AppBuilder();

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
            var builder = new Mock<IAppBuilder>();

            // Act
            builder.Object.UseOpenIdConnectServer(new OpenIdConnectServerOptions());

            // Assert
            builder.Verify(mock => mock.Use(It.IsAny<object>(), It.IsAny<object[]>()), Times.Once());
        }

        [Fact]
        public void EncryptingCredentials_AddKey_ThrowsAnExceptionForNullCredentials()
        {
            // Arrange
            var credentials = (IList<EncryptingCredentials>) null;

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(delegate
            {
                credentials.AddKey(null);
            });

            Assert.Equal("credentials", exception.ParamName);
        }

        [Fact]
        public void EncryptingCredentials_AddKey_ThrowsAnExceptionForNullKey()
        {
            // Arrange
            var credentials = new List<EncryptingCredentials>();

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(delegate
            {
                credentials.AddKey(null);
            });

            Assert.Equal("key", exception.ParamName);
        }

        [Fact]
        public void EncryptingCredentials_AddKey_ThrowsAnExceptionForUnsupportedAlgorithm()
        {
            // Arrange
            var credentials = new List<EncryptingCredentials>();
            var key = Mock.Of<SecurityKey>();

            // Act and assert
            var exception = Assert.Throws<InvalidOperationException>(delegate
            {
                credentials.AddKey(key);
            });

            Assert.Equal("An encryption algorithm cannot be automatically inferred from the encrypting key. " +
                         "Consider using 'options.EncryptingCredentials.Add(EncryptingCredentials)' instead.", exception.Message);
        }

        [Fact]
        public void EncryptingCredentials_AddKey_RegistersCredentials()
        {
            // Arrange
            var credentials = new List<EncryptingCredentials>();
            var factory = Mock.Of<CryptoProviderFactory>(mock => mock.IsSupportedAlgorithm(SecurityAlgorithms.Aes256KW, It.IsAny<SecurityKey>()));
            var key = Mock.Of<SecurityKey>(mock => mock.CryptoProviderFactory == factory);

            // Act
            credentials.AddKey(key);

            // Assert
            Assert.Single(credentials);
            Assert.Equal(SecurityAlgorithms.Aes256KW, credentials[0].Alg);
            Assert.Equal(SecurityAlgorithms.Aes256CbcHmacSha512, credentials[0].Enc);
        }

        [Fact]
        public void SigningCredentials_AddCertificate_ThrowsAnExceptionForNullCredentials()
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
        public void SigningCredentials_AddCertificate_ThrowsAnExceptionForNullCertificate()
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
        public void SigningCredentials_AddCertificate_ThrowsAnExceptionForNullAssembly()
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
        public void SigningCredentials_AddCertificate_ThrowsAnExceptionForNullOrEmptyResource(string resource)
        {
            // Arrange
            var credentials = new List<SigningCredentials>();
            var assembly = typeof(OpenIdConnectServerHandlerTests).GetTypeInfo().Assembly;

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
        public void SigningCredentials_AddCertificate_ThrowsAnExceptionForNullOrEmptyPassword(string password)
        {
            // Arrange
            var credentials = new List<SigningCredentials>();
            var assembly = typeof(OpenIdConnectServerHandlerTests).GetTypeInfo().Assembly;
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
        public void SigningCredentials_AddCertificate_ThrowsAnExceptionForNullOrEmptyThumbprint(string thumbprint)
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
        public void SigningCredentials_AddCertificate_ThrowsAnExceptionForInvalidResource()
        {
            // Arrange
            var credentials = new List<SigningCredentials>();
            var assembly = typeof(OpenIdConnectServerHandlerTests).GetTypeInfo().Assembly;

            // Act and assert
            var exception = Assert.Throws<InvalidOperationException>(delegate
            {
                credentials.AddCertificate(assembly, "resource", "password");
            });

            Assert.Equal("The certificate was not found in the specified assembly.", exception.Message);
        }

        [Fact]
        public void SigningCredentials_AddCertificate_ThrowsAnExceptionForInvalidThumbprint()
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
        public void SigningCredentials_AddCertificate_ThrowsAnExceptionForCertificateWithNoPrivateKey()
        {
            // Arrange
            var credentials = new List<SigningCredentials>();
            var assembly = typeof(OpenIdConnectServerHandlerTests).GetTypeInfo().Assembly;
            var resource = "Owin.Security.OpenIdConnect.Server.Tests.Certificate.cer";

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
        public void SigningCredentials_AddCertificate_RegistersCredentials()
        {
            // Arrange
            var credentials = new List<SigningCredentials>();

            // Act
            credentials.AddCertificate(
                assembly: typeof(OpenIdConnectServerHandlerTests).GetTypeInfo().Assembly,
                resource: "Owin.Security.OpenIdConnect.Server.Tests.Certificate.pfx",
                password: "Owin.Security.OpenIdConnect.Server");

            // Assert
            Assert.Single(credentials);
            Assert.Equal(SecurityAlgorithms.RsaSha256, credentials[0].Algorithm);
            Assert.NotNull(credentials[0].Kid);
        }

        [Fact]
        public void SigningCredentials_AddEphemeralKeyThrowsAnExceptionForNullCredentials()
        {
            // Arrange
            var credentials = (IList<SigningCredentials>) null;

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(delegate
            {
                credentials.AddEphemeralKey(SecurityAlgorithms.RsaSha256);
            });

            Assert.Equal("credentials", exception.ParamName);
        }

        [Theory]
        [InlineData("")]
        [InlineData(null)]
        public void SigningCredentials_AddEphemeralKeyThrowsAnExceptionForNullOrEmptyAlgorithm(string algorithm)
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
        [InlineData(SecurityAlgorithms.EcdsaSha256)]
        [InlineData(SecurityAlgorithms.EcdsaSha384)]
        [InlineData(SecurityAlgorithms.EcdsaSha512)]
        [InlineData(SecurityAlgorithms.EcdsaSha256Signature)]
        [InlineData(SecurityAlgorithms.EcdsaSha384Signature)]
        [InlineData(SecurityAlgorithms.EcdsaSha512Signature)]
        public void SigningCredentials_AddEphemeralKeyThrowsAnExceptionForEcdsaAlgorithmsOnUnsupportedPlatforms(string algorithm)
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
        [InlineData(SecurityAlgorithms.HmacSha256)]
        [InlineData(SecurityAlgorithms.HmacSha384)]
        [InlineData(SecurityAlgorithms.HmacSha512)]
        [InlineData(SecurityAlgorithms.HmacSha256Signature)]
        [InlineData(SecurityAlgorithms.HmacSha384Signature)]
        [InlineData(SecurityAlgorithms.HmacSha512Signature)]
        public void SigningCredentials_AddEphemeralKeyThrowsAnExceptionForUnsupportedAlgorithms(string algorithm)
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
        [InlineData(SecurityAlgorithms.RsaSha256)]
        [InlineData(SecurityAlgorithms.RsaSha384)]
        [InlineData(SecurityAlgorithms.RsaSha512)]
#if SUPPORTS_ECDSA
        [InlineData(SecurityAlgorithms.EcdsaSha256)]
        [InlineData(SecurityAlgorithms.EcdsaSha384)]
        [InlineData(SecurityAlgorithms.EcdsaSha512)]
#endif
        public void SigningCredentials_AddEphemeralKeyRegistersSigningCredentials(string algorithm)
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
        public void SigningCredentials_AddEphemeralKeyUsesRsaSha256ByDefault()
        {
            // Arrange
            var credentials = new List<SigningCredentials>();

            // Act
            credentials.AddEphemeralKey();

            // Assert
            Assert.Single(credentials);
            Assert.Equal(SecurityAlgorithms.RsaSha256, credentials[0].Algorithm);
            Assert.NotNull(credentials[0].Kid);
        }

        [Fact]
        public void SigningCredentials_AddKey_ThrowsAnExceptionForNullCredentials()
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
        public void SigningCredentials_AddKey_ThrowsAnExceptionForNullKey()
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
        public void SigningCredentials_AddKey_ThrowsAnExceptionForNonPrivateKey()
        {
            // Arrange
            var credentials = new List<SigningCredentials>();
            var key = Mock.Of<AsymmetricSecurityKey>(mock => mock.PrivateKeyStatus == PrivateKeyStatus.DoesNotExist);

            // Act and assert
            var exception = Assert.Throws<InvalidOperationException>(delegate
            {
                credentials.AddKey(key);
            });

            Assert.Equal("The asymmetric signing key doesn't contain the required private key.", exception.Message);
        }

#if !SUPPORTS_ECDSA
        [Fact]
        public void SigningCredentials_AddKey_ThrowsAnExceptionForEcdsaKeyOnUnsupportedPlatforms()
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
        public void SigningCredentials_AddKey_ThrowsAnExceptionForUnsupportedAlgorithm()
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
        [InlineData(SecurityAlgorithms.HmacSha256)]
        [InlineData(SecurityAlgorithms.RsaSha256)]
#if SUPPORTS_ECDSA
        [InlineData(SecurityAlgorithms.EcdsaSha256)]
        [InlineData(SecurityAlgorithms.EcdsaSha384)]
        [InlineData(SecurityAlgorithms.EcdsaSha512)]
#endif
        public void SigningCredentials_AddKey_RegistersSigningCredentials(string algorithm)
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
            var context = (IOwinContext) null;

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
            var context = new OwinContext();

            // Act and assert
            Assert.Null(context.GetOpenIdConnectRequest());
        }

        [Fact]
        public void GetOpenIdConnectRequest_ReturnsExpectedRequest()
        {
            // Arrange
            var request = new OpenIdConnectRequest();
            var context = new OwinContext();
            context.Set(typeof(OpenIdConnectRequest).FullName, request);

            // Act and assert
            Assert.Same(request, context.GetOpenIdConnectRequest());
        }

        [Fact]
        public void GetOpenIdConnectResponse_ThrowsAnExceptionForNullContext()
        {
            // Arrange
            var context = (IOwinContext) null;

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
            var context = new OwinContext();

            // Act and assert
            Assert.Null(context.GetOpenIdConnectResponse());
        }

        [Fact]
        public void GetOpenIdConnectResponse_ReturnsExpectedResponse()
        {
            // Arrange
            var response = new OpenIdConnectResponse();
            var context = new OwinContext();
            context.Set(typeof(OpenIdConnectResponse).FullName, response);

            // Act and assert
            Assert.Same(response, context.GetOpenIdConnectResponse());
        }

        [Fact]
        public void SetOpenIdConnectRequest_ThrowsAnExceptionForNullContext()
        {
            // Arrange
            var context = (IOwinContext) null;

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
            var context = new OwinContext();

            // Act
            context.SetOpenIdConnectRequest(request: null);

            // Assert
            Assert.Null(context.Get<OpenIdConnectRequest>(typeof(OpenIdConnectRequest).FullName));
        }

        [Fact]
        public void SetOpenIdConnectRequest_AttachesRequest()
        {
            // Arrange
            var request = new OpenIdConnectRequest();
            var context = new OwinContext();

            // Act
            context.SetOpenIdConnectRequest(request);

            // Assert
            Assert.Same(request, context.Get<OpenIdConnectRequest>(typeof(OpenIdConnectRequest).FullName));
        }

        [Fact]
        public void SetOpenIdConnectResponse_ThrowsAnExceptionForNullContext()
        {
            // Arrange
            var context = (IOwinContext) null;

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
            var context = new OwinContext();

            // Act
            context.SetOpenIdConnectResponse(response: null);

            // Assert
            Assert.Null(context.Get<OpenIdConnectResponse>(typeof(OpenIdConnectResponse).FullName));
        }

        [Fact]
        public void SetOpenIdConnectResponse_AttachesResponse()
        {
            // Arrange
            var response = new OpenIdConnectResponse();
            var context = new OwinContext();

            // Act
            context.SetOpenIdConnectResponse(response);

            // Assert
            Assert.Same(response, context.Get<OpenIdConnectResponse>(typeof(OpenIdConnectResponse).FullName));
        }
    }
}