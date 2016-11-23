/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using Moq;
using Newtonsoft.Json.Linq;
using Xunit;

namespace AspNet.Security.OpenIdConnect.Primitives.Tests {
    public class OpenIdConnectMessageTests {
        [Fact]
        public void GetParameter_ReturnsExpectedParameter() {
            // Arrange
            var value = new JValue(42);

            var message = Mock.Of<OpenIdConnectMessage>();
            Mock.Get(message).CallBase = true;

            message.SetParameter("parameter", value);

            // Act and assert
            Assert.Same(value, message.GetParameter("parameter"));
        }

        [Fact]
        public void GetParameter_IsCaseSensitive() {
            // Arrange
            var value = new JValue(42);

            var message = Mock.Of<OpenIdConnectMessage>();
            Mock.Get(message).CallBase = true;

            message.SetParameter("parameter", value);

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
        public void GetParameter_CanConvertArrayValues() {
            // Arrange
            var message = Mock.Of<OpenIdConnectMessage>();
            Mock.Get(message).CallBase = true;

            message.SetParameter("decimal", new JArray(decimal.MaxValue));
            message.SetParameter("double", new JArray(double.MaxValue));
            message.SetParameter("float", new JArray(float.MaxValue));
            message.SetParameter("int", new JArray(int.MaxValue));
            message.SetParameter("long", new JArray(long.MaxValue));
            message.SetParameter("string", new JArray("value"));

            // Act and assert
            Assert.Equal(new[] { decimal.MaxValue }, message.GetParameter<decimal[]>("decimal"));
            Assert.Equal(new[] { double.MaxValue }, message.GetParameter<double[]>("double"));
            Assert.Equal(new[] { float.MaxValue }, message.GetParameter<float[]>("float"));
            Assert.Equal(new[] { int.MaxValue }, message.GetParameter<int[]>("int"));
            Assert.Equal(new[] { long.MaxValue }, message.GetParameter<long[]>("long"));
            Assert.Equal(new[] { "value" }, message.GetParameter<string[]>("string"));
        }

        [Fact]
        public void GetParameter_CanConvertIntegerValues() {
            // Arrange
            var message = Mock.Of<OpenIdConnectMessage>();
            Mock.Get(message).CallBase = true;

            message.SetParameter("decimal", decimal.MaxValue);
            message.SetParameter("double", double.MaxValue);
            message.SetParameter("float", float.MaxValue);
            message.SetParameter("int", int.MaxValue);
            message.SetParameter("long", long.MaxValue);

            // Act and assert
            Assert.Equal(decimal.MaxValue.ToString(CultureInfo.InvariantCulture), message.GetParameter<string>("decimal"));
            Assert.Equal(double.MaxValue.ToString(CultureInfo.InvariantCulture), message.GetParameter<string>("double"));
            Assert.Equal(float.MaxValue.ToString(CultureInfo.InvariantCulture), message.GetParameter<string>("float"));
            Assert.Equal(int.MaxValue.ToString(CultureInfo.InvariantCulture), message.GetParameter<string>("int"));
            Assert.Equal(long.MaxValue.ToString(CultureInfo.InvariantCulture), message.GetParameter<string>("long"));
        }

        [Fact]
        public void GetParameter_CanConvertStringValues() {
            // Arrange
            var message = Mock.Of<OpenIdConnectMessage>();
            Mock.Get(message).CallBase = true;

            message.SetParameter("decimal", decimal.MaxValue.ToString(CultureInfo.InvariantCulture));
            message.SetParameter("double", double.MaxValue.ToString("R", CultureInfo.InvariantCulture));
            message.SetParameter("float", float.MaxValue.ToString("R", CultureInfo.InvariantCulture));
            message.SetParameter("int", int.MaxValue.ToString(CultureInfo.InvariantCulture));
            message.SetParameter("long", long.MaxValue.ToString(CultureInfo.InvariantCulture));

            // Act and assert
            Assert.Equal(decimal.MaxValue, message.GetParameter<decimal>("decimal"));
            Assert.Equal(double.MaxValue, message.GetParameter<double>("double"));
            Assert.Equal(float.MaxValue, message.GetParameter<float>("float"));
            Assert.Equal(int.MaxValue, message.GetParameter<int>("int"));
            Assert.Equal(long.MaxValue, message.GetParameter<long>("long"));
        }

        [Fact]
        public void GetParameters_EnumeratesParameters() {
            // Arrange
            var parameters = new Dictionary<string, JToken> {
                ["decimal"] = decimal.MaxValue,
                ["double"] = double.MaxValue,
                ["float"] = float.MaxValue,
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
            var message = Mock.Of<OpenIdConnectMessage>();
            Mock.Get(message).CallBase = true;

            message.SetProperty("property_1", "value_1");
            message.SetProperty("property_2", "value_2");

            // Act
            var properties = message.GetProperties();

            // Assert
            Assert.Equal(2, properties.Count());
            Assert.Contains(properties, item => item.Key == "property_1" && item.Value == "value_1");
            Assert.Contains(properties, item => item.Key == "property_2" && item.Value == "value_2");
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

        [Fact]
        public void SetParameter_AddsExpectedParameter() {
            // Arrange
            var value = new JValue(42);

            var message = Mock.Of<OpenIdConnectMessage>();
            Mock.Get(message).CallBase = true;

            // Act
            message.SetParameter("parameter", value);

            // Assert
            Assert.Same(value, message.GetParameter("parameter"));
        }

        [Fact]
        public void SetParameter_IsCaseSensitive() {
            // Arrange
            var value = new JValue(42);

            var message = Mock.Of<OpenIdConnectMessage>();
            Mock.Get(message).CallBase = true;

            // Act
            message.SetParameter("PARAMETER", value);

            // Assert
            Assert.Null(message.GetParameter("parameter"));
        }

        [Fact]
        public void SetParameter_RemovesEmptyParameters() {
            // Arrange
            var message = Mock.Of<OpenIdConnectMessage>();
            Mock.Get(message).CallBase = true;

            // Act
            message.SetParameter("array", new JArray());
            message.SetParameter("object", new JObject());
            message.SetParameter("string", string.Empty);

            // Assert
            Assert.Equal(0, message.GetParameters().Count());
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
        public void SetProperty_RemovesEmptyProperty() {
            // Arrange
            var message = Mock.Of<OpenIdConnectMessage>();
            Mock.Get(message).CallBase = true;

            // Act
            message.SetProperty("property", string.Empty);

            // Assert
            Assert.Null(message.GetProperty("property"));
        }
    }
}
