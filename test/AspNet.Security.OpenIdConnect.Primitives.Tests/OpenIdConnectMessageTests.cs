/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.Linq;
using Moq;
using Newtonsoft.Json.Linq;
using Xunit;

namespace AspNet.Security.OpenIdConnect.Primitives.Tests {
    public class OpenIdConnectMessageTests {
        [Fact]
        public void Constructor_ImportsParameters() {
            // Arrange
            var parameters = new[] {
                new KeyValuePair<string, OpenIdConnectParameter>("parameter", 42)
            };

            // Act
            var message = new Mock<OpenIdConnectMessage>(parameters);
            message.CallBase = true;

            // Assert
            Assert.Equal(42, (long) message.Object.GetParameter("parameter"));
        }

        [Fact]
        public void Constructor_IgnoresNamelessParameters() {
            // Arrange
            var parameters = new[] {
                new KeyValuePair<string, OpenIdConnectParameter>(null, new OpenIdConnectParameter()),
                new KeyValuePair<string, OpenIdConnectParameter>(string.Empty, new OpenIdConnectParameter())
            };

            // Act
            var message = new Mock<OpenIdConnectMessage>(parameters);
            message.CallBase = true;

            // Assert
            Assert.Equal(0, message.Object.GetParameters().Count());
        }

        [Fact]
        public void Constructor_PreservesEmptyParameters() {
            // Arrange
            var parameters = new[] {
                new KeyValuePair<string, OpenIdConnectParameter>("parameter", (string) null)
            };

            // Act
            var message = new Mock<OpenIdConnectMessage>(parameters);
            message.CallBase = true;

            // Assert
            Assert.Equal(1, message.Object.GetParameters().Count());
        }

        [Fact]
        public void Constructor_IgnoresDuplicateParameters() {
            // Arrange
            var parameters = new[] {
                new KeyValuePair<string, OpenIdConnectParameter>("parameter", "Fabrikam"),
                new KeyValuePair<string, OpenIdConnectParameter>("parameter", "Contoso")
            };

            // Act
            var message = new Mock<OpenIdConnectMessage>(parameters);
            message.CallBase = true;

            // Assert
            Assert.Equal(1, message.Object.GetParameters().Count());
            Assert.Equal("Fabrikam", message.Object.GetParameter("parameter"));
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        public void AddParameter_ThrowsAnExceptionForNullOrEmptyName(string name) {
            // Arrange
            var message = Mock.Of<OpenIdConnectMessage>();
            Mock.Get(message).CallBase = true;

            // Act and assert
            var exception = Assert.Throws<ArgumentException>(delegate {
                message.AddParameter(name, new OpenIdConnectParameter());
            });

            Assert.Equal("name", exception.ParamName);
            Assert.StartsWith("The parameter name cannot be null or empty.", exception.Message);
        }

        [Fact]
        public void AddParameter_AddsExpectedParameter() {
            // Arrange
            var message = Mock.Of<OpenIdConnectMessage>();
            Mock.Get(message).CallBase = true;

            // Act
            message.AddParameter("parameter", 42);

            // Assert
            Assert.Equal(42, message.GetParameter("parameter"));
        }

        [Fact]
        public void AddParameter_IsCaseSensitive() {
            // Arrange
            var message = Mock.Of<OpenIdConnectMessage>();
            Mock.Get(message).CallBase = true;

            // Act
            message.AddParameter("PARAMETER", 42);

            // Assert
            Assert.Null(message.GetParameter("parameter"));
        }

        [Fact]
        public void AddParameter_PreservesEmptyParameters() {
            // Arrange
            var message = Mock.Of<OpenIdConnectMessage>();
            Mock.Get(message).CallBase = true;

            // Act
            message.AddParameter("string", string.Empty);
            message.AddParameter("array", new JArray());
            message.AddParameter("object", new JObject());
            message.AddParameter("value", new JValue(string.Empty));

            // Assert
            Assert.Empty((string) message.GetParameter("string"));
            Assert.Equal(new JArray(), (JArray) message.GetParameter("array"));
            Assert.Equal(new JObject(), (JObject) message.GetParameter("object"));
            Assert.Equal(new JValue(string.Empty), (JValue) message.GetParameter("value"));
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        public void AddProperty_ThrowsAnExceptionForNullOrEmptyName(string name) {
            // Arrange
            var message = Mock.Of<OpenIdConnectMessage>();
            Mock.Get(message).CallBase = true;

            // Act and assert
            var exception = Assert.Throws<ArgumentException>(delegate {
                message.AddProperty(name, null);
            });

            Assert.Equal("name", exception.ParamName);
            Assert.StartsWith("The property name cannot be null or empty.", exception.Message);
        }

        [Fact]
        public void AddProperty_AddsExpectedProperty() {
            // Arrange
            var message = Mock.Of<OpenIdConnectMessage>();
            Mock.Get(message).CallBase = true;

            // Act
            message.AddProperty("property", "value");

            // Assert
            Assert.Equal("value", message.GetProperty("property"));
        }

        [Fact]
        public void AddProperty_IsCaseSensitive() {
            // Arrange
            var message = Mock.Of<OpenIdConnectMessage>();
            Mock.Get(message).CallBase = true;

            // Act
            message.AddProperty("PROPERTY", "value");

            // Assert
            Assert.Null(message.GetProperty("property"));
        }

        [Fact]
        public void AddProperty_PreservesEmptyProperties() {
            // Arrange
            var message = Mock.Of<OpenIdConnectMessage>();
            Mock.Get(message).CallBase = true;

            // Act
            message.AddProperty("property", string.Empty);

            // Assert
            Assert.Empty(message.GetProperty<string>("property"));
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        public void GetParameter_ThrowsAnExceptionForNullOrEmptyName(string name) {
            // Arrange
            var message = Mock.Of<OpenIdConnectMessage>();
            Mock.Get(message).CallBase = true;

            // Act and assert
            var exception = Assert.Throws<ArgumentException>(delegate {
                message.GetParameter(name);
            });

            Assert.Equal("name", exception.ParamName);
            Assert.StartsWith("The parameter name cannot be null or empty.", exception.Message);
        }

        [Fact]
        public void GetParameter_ReturnsExpectedParameter() {
            // Arrange
            var message = Mock.Of<OpenIdConnectMessage>();
            Mock.Get(message).CallBase = true;

            message.SetParameter("parameter", 42);

            // Act and assert
            Assert.Equal(42, (int) message.GetParameter("parameter"));
        }

        [Fact]
        public void GetParameter_IsCaseSensitive() {
            // Arrange
            var message = Mock.Of<OpenIdConnectMessage>();
            Mock.Get(message).CallBase = true;

            message.SetParameter("parameter", 42);

            // Act and assert
            Assert.Null(message.GetParameter("PARAMETER"));
        }

        [Fact]
        public void GetParameter_ReturnsNullForUnsetParameter() {
            // Arrange
            var message = Mock.Of<OpenIdConnectMessage>();
            Mock.Get(message).CallBase = true;

            // Act and assert
            Assert.Null(message.GetParameter("parameter"));
        }

        [Fact]
        public void GetParameters_EnumeratesParameters() {
            // Arrange
            var parameters = new Dictionary<string, OpenIdConnectParameter> {
                ["int"] = int.MaxValue,
                ["long"] = long.MaxValue,
                ["string"] = "value"
            };

            var message = new Mock<OpenIdConnectMessage>(parameters);
            message.CallBase = true;

            // Act and assert
            Assert.Equal(parameters, message.Object.GetParameters());
        }

        [Fact]
        public void GetProperties_EnumeratesProperties() {
            // Arrange
            var properties = new Dictionary<string, object> {
                ["int"] = int.MaxValue,
                ["long"] = long.MaxValue,
                ["object"] = new object(),
                ["string"] = "value"
            };

            var message = Mock.Of<OpenIdConnectMessage>();
            Mock.Get(message).CallBase = true;

            foreach (var property in properties) {
                message.SetProperty(property.Key, property.Value);
            }

            // Act and assert
            Assert.Equal(properties, message.GetProperties());
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        public void GetProperty_ThrowsAnExceptionForNullOrEmptyName(string name) {
            // Arrange
            var message = Mock.Of<OpenIdConnectMessage>();
            Mock.Get(message).CallBase = true;

            // Act and assert
            var exception = Assert.Throws<ArgumentException>(delegate {
                message.GetProperty(name);
            });

            Assert.Equal("name", exception.ParamName);
            Assert.StartsWith("The property name cannot be null or empty.", exception.Message);
        }

        [Fact]
        public void GetProperty_ReturnsDefaultInstanceForMissingProperty() {
            // Arrange
            var message = Mock.Of<OpenIdConnectMessage>();
            Mock.Get(message).CallBase = true;

            // Act and assert
            Assert.Equal(0, message.GetProperty<long>("property"));
        }

        [Fact]
        public void GetProperty_ReturnsDefaultInstanceForInvalidType() {
            // Arrange
            var message = Mock.Of<OpenIdConnectMessage>();
            Mock.Get(message).CallBase = true;

            message.SetProperty("property", "value");

            // Act and assert
            Assert.Equal(0, message.GetProperty<long>("property"));
        }

        [Theory]
        [InlineData("property", "value")]
        [InlineData("PROPERTY", null)]
        [InlineData("missing_property", null)]
        public void GetProperty_ReturnsExpectedResult(string property, object result) {
            // Arrange
            var message = Mock.Of<OpenIdConnectMessage>();
            Mock.Get(message).CallBase = true;

            message.SetProperty("property", "value");

            // Act and assert
            Assert.Equal(result, message.GetProperty(property));
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        public void HasParameter_ThrowsAnExceptionForNullOrEmptyName(string name) {
            // Arrange
            var message = Mock.Of<OpenIdConnectMessage>();
            Mock.Get(message).CallBase = true;

            // Act and assert
            var exception = Assert.Throws<ArgumentException>(delegate {
                message.HasParameter(name);
            });

            Assert.Equal("name", exception.ParamName);
            Assert.StartsWith("The parameter name cannot be null or empty.", exception.Message);
        }

        [Theory]
        [InlineData("parameter", true)]
        [InlineData("PARAMETER", false)]
        [InlineData("missing_parameter", false)]
        public void HasParameter_ReturnsExpectedResult(string parameter, bool result) {
            // Arrange
            var message = Mock.Of<OpenIdConnectMessage>();
            Mock.Get(message).CallBase = true;

            message.SetParameter("parameter", "value");

            // Act and assert
            Assert.Equal(result, message.HasParameter(parameter));
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        public void HasProperty_ThrowsAnExceptionForNullOrEmptyName(string name) {
            // Arrange
            var message = Mock.Of<OpenIdConnectMessage>();
            Mock.Get(message).CallBase = true;

            // Act and assert
            var exception = Assert.Throws<ArgumentException>(delegate {
                message.HasProperty(name);
            });

            Assert.Equal("name", exception.ParamName);
            Assert.StartsWith("The property name cannot be null or empty.", exception.Message);
        }

        [Theory]
        [InlineData("property", true)]
        [InlineData("PROPERTY", false)]
        [InlineData("missing_property", false)]
        public void HasProperty_ReturnsExpectedResult(string property, bool result) {
            // Arrange
            var message = Mock.Of<OpenIdConnectMessage>();
            Mock.Get(message).CallBase = true;

            message.SetProperty("property", "value");

            // Act and assert
            Assert.Equal(result, message.HasProperty(property));
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        public void SetParameter_ThrowsAnExceptionForNullOrEmptyName(string name) {
            // Arrange
            var message = Mock.Of<OpenIdConnectMessage>();
            Mock.Get(message).CallBase = true;

            // Act and assert
            var exception = Assert.Throws<ArgumentException>(delegate {
                message.SetParameter(name, null);
            });

            Assert.Equal("name", exception.ParamName);
            Assert.StartsWith("The parameter name cannot be null or empty.", exception.Message);
        }

        [Fact]
        public void SetParameter_AddsExpectedParameter() {
            // Arrange
            var message = Mock.Of<OpenIdConnectMessage>();
            Mock.Get(message).CallBase = true;

            // Act
            message.SetParameter("parameter", 42);

            // Assert
            Assert.Equal(42, message.GetParameter("parameter"));
        }

        [Fact]
        public void SetParameter_IsCaseSensitive() {
            // Arrange
            var message = Mock.Of<OpenIdConnectMessage>();
            Mock.Get(message).CallBase = true;

            // Act
            message.SetParameter("PARAMETER", 42);

            // Assert
            Assert.Null(message.GetParameter("parameter"));
        }

        [Fact]
        public void SetParameter_RemovesNullParameters() {
            // Arrange
            var message = Mock.Of<OpenIdConnectMessage>();
            Mock.Get(message).CallBase = true;

            // Act
            message.SetParameter("null", null);

            // Assert
            Assert.Equal(0, message.GetParameters().Count());
        }

        [Fact]
        public void SetParameter_RemovesEmptyParameters() {
            // Arrange
            var message = Mock.Of<OpenIdConnectMessage>();
            Mock.Get(message).CallBase = true;

            // Act
            message.SetParameter("string", string.Empty);
            message.SetParameter("array", new JArray());
            message.SetParameter("object", new JObject());
            message.SetParameter("value", new JValue(string.Empty));

            // Assert
            Assert.Equal(0, message.GetParameters().Count());
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        public void SetProperty_ThrowsAnExceptionForNullOrEmptyName(string name) {
            // Arrange
            var message = Mock.Of<OpenIdConnectMessage>();
            Mock.Get(message).CallBase = true;

            // Act and assert
            var exception = Assert.Throws<ArgumentException>(delegate {
                message.SetProperty(name, null);
            });

            Assert.Equal("name", exception.ParamName);
            Assert.StartsWith("The property name cannot be null or empty.", exception.Message);
        }

        [Fact]
        public void SetProperty_AddsExpectedProperty() {
            // Arrange
            var message = Mock.Of<OpenIdConnectMessage>();
            Mock.Get(message).CallBase = true;

            // Act
            message.SetProperty("property", "value");

            // Assert
            Assert.Equal("value", message.GetProperty("property"));
        }

        [Fact]
        public void SetProperty_IsCaseSensitive() {
            // Arrange
            var message = Mock.Of<OpenIdConnectMessage>();
            Mock.Get(message).CallBase = true;

            // Act
            message.SetProperty("PROPERTY", "value");

            // Assert
            Assert.Null(message.GetProperty("property"));
        }

        [Fact]
        public void SetProperty_RemovesEmptyProperties() {
            // Arrange
            var message = Mock.Of<OpenIdConnectMessage>();
            Mock.Get(message).CallBase = true;

            // Act
            message.SetProperty("property", string.Empty);

            // Assert
            Assert.Null(message.GetProperty("property"));
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        public void RemoveParameter_ThrowsAnExceptionForNullOrEmptyName(string name) {
            // Arrange
            var message = Mock.Of<OpenIdConnectMessage>();
            Mock.Get(message).CallBase = true;

            // Act and assert
            var exception = Assert.Throws<ArgumentException>(delegate {
                message.RemoveParameter(name);
            });

            Assert.Equal("name", exception.ParamName);
            Assert.StartsWith("The parameter name cannot be null or empty.", exception.Message);
        }

        [Fact]
        public void RemoveParameter_RemovesExpectedParameter() {
            // Arrange
            var message = Mock.Of<OpenIdConnectMessage>();
            Mock.Get(message).CallBase = true;

            message.AddParameter("parameter", 42);

            // Act
            message.RemoveParameter("parameter");

            // Assert
            Assert.Null(message.GetParameter("parameter"));
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        public void RemoveProperty_ThrowsAnExceptionForNullOrEmptyName(string name) {
            // Arrange
            var message = Mock.Of<OpenIdConnectMessage>();
            Mock.Get(message).CallBase = true;

            // Act and assert
            var exception = Assert.Throws<ArgumentException>(delegate {
                message.RemoveProperty(name);
            });

            Assert.Equal("name", exception.ParamName);
            Assert.StartsWith("The property name cannot be null or empty.", exception.Message);
        }

        [Fact]
        public void RemoveProperty_RemovesExpectedProperty() {
            // Arrange
            var message = Mock.Of<OpenIdConnectMessage>();
            Mock.Get(message).CallBase = true;

            message.AddProperty("property", 42);

            // Act
            message.RemoveProperty("property");

            // Assert
            Assert.Null(message.GetProperty("property"));
        }
    }
}
