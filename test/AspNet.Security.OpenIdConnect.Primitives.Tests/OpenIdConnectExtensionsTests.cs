/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using Xunit;

namespace AspNet.Security.OpenIdConnect.Primitives.Tests
{
    public class OpenIdConnectExtensionsTests
    {
        [Theory]
        [InlineData(null, new string[0])]
        [InlineData("fabrikam", new[] { "fabrikam" })]
        [InlineData("fabrikam ", new[] { "fabrikam" })]
        [InlineData(" fabrikam ", new[] { "fabrikam" })]
        [InlineData("fabrikam contoso", new[] { "fabrikam", "contoso" })]
        [InlineData("fabrikam     contoso", new[] { "fabrikam", "contoso" })]
        [InlineData("fabrikam contoso ", new[] { "fabrikam", "contoso" })]
        [InlineData(" fabrikam contoso", new[] { "fabrikam", "contoso" })]
        [InlineData("fabrikam fabrikam contoso", new[] { "fabrikam", "contoso" })]
        [InlineData("fabrikam FABRIKAM contoso", new[] { "fabrikam", "FABRIKAM", "contoso" })]
        public void GetResources_ReturnsExpectedResources(string resource, string[] resources)
        {
            // Arrange
            var request = new OpenIdConnectRequest();
            request.Resource = resource;

            // Act and assert
            Assert.Equal(resources, request.GetResources());
        }

        [Theory]
        [InlineData(null, new string[0])]
        [InlineData("openid", new[] { "openid" })]
        [InlineData("openid ", new[] { "openid" })]
        [InlineData(" openid ", new[] { "openid" })]
        [InlineData("openid profile", new[] { "openid", "profile" })]
        [InlineData("openid     profile", new[] { "openid", "profile" })]
        [InlineData("openid profile ", new[] { "openid", "profile" })]
        [InlineData(" openid profile", new[] { "openid", "profile" })]
        [InlineData("openid openid profile", new[] { "openid", "profile" })]
        [InlineData("openid OPENID profile", new[] { "openid", "OPENID", "profile" })]
        public void GetScopes_ReturnsExpectedScopes(string scope, string[] scopes)
        {
            // Arrange
            var request = new OpenIdConnectRequest();
            request.Scope = scope;

            // Act and assert
            Assert.Equal(scopes, request.GetScopes());
        }

        [Theory]
        [InlineData(null, false)]
        [InlineData("code", true)]
        [InlineData("code id_token", true)]
        [InlineData(" code id_token", true)]
        [InlineData("id_token code", true)]
        [InlineData("id_token code ", true)]
        [InlineData("id_token code token", true)]
        [InlineData("id_token code token ", true)]
        [InlineData("id_token    code   token ", true)]
        [InlineData("id_token", false)]
        [InlineData("id_token token", false)]
        [InlineData("CODE", false)]
        [InlineData("CODE ID_TOKEN", false)]
        [InlineData(" CODE ID_TOKEN", false)]
        [InlineData("ID_TOKEN CODE", false)]
        [InlineData("ID_TOKEN CODE ", false)]
        [InlineData("ID_TOKEN CODE TOKEN", false)]
        [InlineData("ID_TOKEN CODE TOKEN ", false)]
        [InlineData("ID_TOKEN    CODE   TOKEN ", false)]
        [InlineData("ID_TOKEN", false)]
        [InlineData("ID_TOKEN TOKEN", false)]
        public void HasResponseType_ReturnsExpectedResult(string type, bool result)
        {
            // Arrange
            var request = new OpenIdConnectRequest();
            request.ResponseType = type;

            // Act and assert
            Assert.Equal(result, request.HasResponseType(OpenIdConnectConstants.ResponseTypes.Code));
        }

        [Theory]
        [InlineData(null, false)]
        [InlineData("openid", true)]
        [InlineData("openid ", true)]
        [InlineData(" openid ", true)]
        [InlineData("openid profile", true)]
        [InlineData("openid     profile", true)]
        [InlineData("openid profile ", true)]
        [InlineData(" openid profile", true)]
        [InlineData("profile", false)]
        [InlineData("profile email", false)]
        [InlineData("OPENID", false)]
        [InlineData("OPENID ", false)]
        [InlineData(" OPENID ", false)]
        [InlineData("OPENID PROFILE", false)]
        [InlineData("OPENID     PROFILE", false)]
        [InlineData("OPENID PROFILE ", false)]
        [InlineData(" OPENID PROFILE", false)]
        [InlineData("PROFILE", false)]
        [InlineData("PROFILE EMAIL", false)]
        public void HasScope_ReturnsExpectedResult(string scope, bool result)
        {
            // Arrange
            var request = new OpenIdConnectRequest();
            request.Scope = scope;

            // Act and assert
            Assert.Equal(result, request.HasScope(OpenIdConnectConstants.Scopes.OpenId));
        }

        [Theory]
        [InlineData(null, false)]
        [InlineData("unknown", false)]
        [InlineData(OpenIdConnectConstants.MessageTypes.AuthorizationRequest, true)]
        public void IsAuthorizationRequest_ReturnsExpectedResult(string type, bool result)
        {
            // Arrange
            var request = new OpenIdConnectRequest();
            request.SetProperty(OpenIdConnectConstants.Properties.MessageType, type);

            // Act and assert
            Assert.Equal(result, request.IsAuthorizationRequest());
        }

        [Theory]
        [InlineData(null, false)]
        [InlineData("unknown", false)]
        [InlineData(OpenIdConnectConstants.ConfidentialityLevels.Private, true)]
        [InlineData(OpenIdConnectConstants.ConfidentialityLevels.Public, false)]
        public void IsConfidential_ReturnsExpectedResult(string level, bool result)
        {
            // Arrange
            var request = new OpenIdConnectRequest();
            request.SetProperty(OpenIdConnectConstants.Properties.ConfidentialityLevel, level);

            // Act and assert
            Assert.Equal(result, request.IsConfidential());
        }

        [Theory]
        [InlineData(null, false)]
        [InlineData("unknown", false)]
        [InlineData(OpenIdConnectConstants.MessageTypes.ConfigurationRequest, true)]
        public void IsConfigurationRequest_ReturnsExpectedResult(string type, bool result)
        {
            // Arrange
            var request = new OpenIdConnectRequest();
            request.SetProperty(OpenIdConnectConstants.Properties.MessageType, type);

            // Act and assert
            Assert.Equal(result, request.IsConfigurationRequest());
        }

        [Theory]
        [InlineData(null, false)]
        [InlineData("unknown", false)]
        [InlineData(OpenIdConnectConstants.MessageTypes.CryptographyRequest, true)]
        public void IsCryptographyRequest_ReturnsExpectedResult(string type, bool result)
        {
            // Arrange
            var request = new OpenIdConnectRequest();
            request.SetProperty(OpenIdConnectConstants.Properties.MessageType, type);

            // Act and assert
            Assert.Equal(result, request.IsCryptographyRequest());
        }

        [Theory]
        [InlineData(null, false)]
        [InlineData("unknown", false)]
        [InlineData(OpenIdConnectConstants.MessageTypes.IntrospectionRequest, true)]
        public void IsIntrospectionRequest_ReturnsExpectedResult(string type, bool result)
        {
            // Arrange
            var request = new OpenIdConnectRequest();
            request.SetProperty(OpenIdConnectConstants.Properties.MessageType, type);

            // Act and assert
            Assert.Equal(result, request.IsIntrospectionRequest());
        }

        [Theory]
        [InlineData(null, false)]
        [InlineData("unknown", false)]
        [InlineData(OpenIdConnectConstants.MessageTypes.LogoutRequest, true)]
        public void IsLogoutRequest_ReturnsExpectedResult(string type, bool result)
        {
            // Arrange
            var request = new OpenIdConnectRequest();
            request.SetProperty(OpenIdConnectConstants.Properties.MessageType, type);

            // Act and assert
            Assert.Equal(result, request.IsLogoutRequest());
        }

        [Theory]
        [InlineData(null, false)]
        [InlineData("unknown", false)]
        [InlineData(OpenIdConnectConstants.MessageTypes.RevocationRequest, true)]
        public void IsRevocationRequest_ReturnsExpectedResult(string type, bool result)
        {
            // Arrange
            var request = new OpenIdConnectRequest();
            request.SetProperty(OpenIdConnectConstants.Properties.MessageType, type);

            // Act and assert
            Assert.Equal(result, request.IsRevocationRequest());
        }

        [Theory]
        [InlineData(null, false)]
        [InlineData("unknown", false)]
        [InlineData(OpenIdConnectConstants.MessageTypes.TokenRequest, true)]
        public void IsTokenRequest_ReturnsExpectedResult(string type, bool result)
        {
            // Arrange
            var request = new OpenIdConnectRequest();
            request.SetProperty(OpenIdConnectConstants.Properties.MessageType, type);

            // Act and assert
            Assert.Equal(result, request.IsTokenRequest());
        }

        [Theory]
        [InlineData(null, false)]
        [InlineData("unknown", false)]
        [InlineData(OpenIdConnectConstants.MessageTypes.UserinfoRequest, true)]
        public void IsUserinfoRequest_ReturnsExpectedResult(string type, bool result)
        {
            // Arrange
            var request = new OpenIdConnectRequest();
            request.SetProperty(OpenIdConnectConstants.Properties.MessageType, type);

            // Act and assert
            Assert.Equal(result, request.IsUserinfoRequest());
        }

        [Theory]
        [InlineData(null, false)]
        [InlineData("unknown", false)]
        [InlineData("none", true)]
        [InlineData("none ", true)]
        [InlineData(" none", true)]
        [InlineData("none id_token", false)]
        [InlineData(" none id_token", false)]
        [InlineData("none id_token ", false)]
        [InlineData(" none id_token ", false)]
        [InlineData("NONE", false)]
        [InlineData("NONE ", false)]
        [InlineData(" NONE", false)]
        [InlineData("NONE ID_TOKEN", false)]
        [InlineData(" NONE ID_TOKEN", false)]
        [InlineData("NONE ID_TOKEN ", false)]
        [InlineData(" NONE ID_TOKEN ", false)]
        public void IsNoneFlow_ReturnsExpectedResult(string type, bool result)
        {
            // Arrange
            var request = new OpenIdConnectRequest();
            request.ResponseType = type;

            // Act and assert
            Assert.Equal(result, request.IsNoneFlow());
        }

        [Theory]
        [InlineData(null, false)]
        [InlineData("unknown", false)]
        [InlineData("code", true)]
        [InlineData("code ", true)]
        [InlineData(" code", true)]
        [InlineData("code id_token", false)]
        [InlineData(" code id_token", false)]
        [InlineData("code id_token ", false)]
        [InlineData(" code id_token ", false)]
        [InlineData("CODE", false)]
        [InlineData("CODE ", false)]
        [InlineData(" CODE", false)]
        [InlineData("CODE ID_TOKEN", false)]
        [InlineData(" CODE ID_TOKEN", false)]
        [InlineData("CODE ID_TOKEN ", false)]
        [InlineData(" CODE ID_TOKEN ", false)]
        public void IsAuthorizationCodeFlow_ReturnsExpectedResult(string type, bool result)
        {
            // Arrange
            var request = new OpenIdConnectRequest();
            request.ResponseType = type;

            // Act and assert
            Assert.Equal(result, request.IsAuthorizationCodeFlow());
        }

        [Theory]
        [InlineData(null, false)]
        [InlineData("unknown", false)]
        [InlineData("id_token", true)]
        [InlineData("id_token ", true)]
        [InlineData(" id_token", true)]
        [InlineData("id_token token", true)]
        [InlineData(" id_token token", true)]
        [InlineData("id_token token ", true)]
        [InlineData(" id_token token ", true)]
        [InlineData("token", true)]
        [InlineData("token ", true)]
        [InlineData(" token", true)]
        [InlineData("code id_token", false)]
        [InlineData("code id_token token", false)]
        [InlineData("code token", false)]
        [InlineData("ID_TOKEN", false)]
        [InlineData("ID_TOKEN ", false)]
        [InlineData(" ID_TOKEN", false)]
        [InlineData("ID_TOKEN TOKEN", false)]
        [InlineData(" ID_TOKEN TOKEN", false)]
        [InlineData("ID_TOKEN TOKEN ", false)]
        [InlineData(" ID_TOKEN TOKEN ", false)]
        [InlineData("TOKEN", false)]
        [InlineData("TOKEN ", false)]
        [InlineData(" TOKEN", false)]
        [InlineData("CODE ID_TOKEN", false)]
        [InlineData("CODE ID_TOKEN TOKEN", false)]
        [InlineData("CODE TOKEN", false)]
        public void IsImplicitFlow_ReturnsExpectedResult(string type, bool result)
        {
            // Arrange
            var request = new OpenIdConnectRequest();
            request.ResponseType = type;

            // Act and assert
            Assert.Equal(result, request.IsImplicitFlow());
        }

        [Theory]
        [InlineData(null, false)]
        [InlineData("unknown", false)]
        [InlineData("code id_token", true)]
        [InlineData("code id_token ", true)]
        [InlineData(" code id_token", true)]
        [InlineData("code id_token token", true)]
        [InlineData(" code id_token token", true)]
        [InlineData("code id_token token ", true)]
        [InlineData(" code id_token token ", true)]
        [InlineData("code id_token token ", true)]
        [InlineData(" code  id_token  token ", true)]
        [InlineData("code token", true)]
        [InlineData("code token ", true)]
        [InlineData(" code token", true)]
        [InlineData("id_token", false)]
        [InlineData("id_token token", false)]
        [InlineData("token", false)]
        [InlineData("CODE ID_TOKEN", false)]
        [InlineData("CODE ID_TOKEN ", false)]
        [InlineData(" CODE ID_TOKEN", false)]
        [InlineData("CODE ID_TOKEN TOKEN", false)]
        [InlineData(" CODE ID_TOKEN TOKEN", false)]
        [InlineData("CODE ID_TOKEN TOKEN ", false)]
        [InlineData(" CODE ID_TOKEN TOKEN ", false)]
        [InlineData("CODE ID_TOKEN TOKEN ", false)]
        [InlineData(" CODE  ID_TOKEN  TOKEN ", false)]
        [InlineData("CODE TOKEN", false)]
        [InlineData("CODE TOKEN ", false)]
        [InlineData(" CODE TOKEN", false)]
        [InlineData("ID_TOKEN", false)]
        [InlineData("ID_TOKEN TOKEN", false)]
        [InlineData("TOKEN", false)]
        public void IsHybridFlow_ReturnsExpectedResult(string type, bool result)
        {
            // Arrange
            var request = new OpenIdConnectRequest();
            request.ResponseType = type;

            // Act and assert
            Assert.Equal(result, request.IsHybridFlow());
        }

        [Theory]
        [InlineData(null, null, false)]
        [InlineData("unknown", null, false)]
        [InlineData("query", null, false)]
        [InlineData("form_post", null, false)]
        [InlineData("fragment", null, true)]
        [InlineData("fragment ", null, false)]
        [InlineData(" fragment", null, false)]
        [InlineData(" fragment ", null, false)]
        [InlineData(null, "code", false)]
        [InlineData(null, "code id_token", true)]
        [InlineData(null, "code id_token token", true)]
        [InlineData(null, "code token", true)]
        [InlineData(null, "id_token", true)]
        [InlineData(null, "id_token token", true)]
        [InlineData(null, "token", true)]
        [InlineData("QUERY", null, false)]
        [InlineData("FRAGMENT", null, false)]
        [InlineData("FORM_POST", null, false)]
        [InlineData(null, "CODE", false)]
        [InlineData(null, "CODE ID_TOKEN", false)]
        [InlineData(null, "CODE ID_TOKEN TOKEN", false)]
        [InlineData(null, "CODE TOKEN", false)]
        [InlineData(null, "ID_TOKEN", false)]
        [InlineData(null, "ID_TOKEN TOKEN", false)]
        [InlineData(null, "TOKEN", false)]
        public void IsFragmentResponseMode_ReturnsExpectedResult(string mode, string type, bool result)
        {
            // Arrange
            var request = new OpenIdConnectRequest();
            request.ResponseMode = mode;
            request.ResponseType = type;

            // Act and assert
            Assert.Equal(result, request.IsFragmentResponseMode());
        }

        [Theory]
        [InlineData(null, null, false)]
        [InlineData("unknown", null, false)]
        [InlineData("query", null, true)]
        [InlineData("query ", null, false)]
        [InlineData(" query", null, false)]
        [InlineData(" query ", null, false)]
        [InlineData("fragment", null, false)]
        [InlineData("form_post", null, false)]
        [InlineData(null, "none", true)]
        [InlineData(null, "code", true)]
        [InlineData(null, "code id_token token", false)]
        [InlineData(null, "code token", false)]
        [InlineData(null, "id_token", false)]
        [InlineData(null, "id_token token", false)]
        [InlineData(null, "token", false)]
        [InlineData("QUERY", null, false)]
        [InlineData("FRAGMENT", null, false)]
        [InlineData("FORM_POST", null, false)]
        [InlineData(null, "CODE", false)]
        [InlineData(null, "CODE ID_TOKEN", false)]
        [InlineData(null, "CODE ID_TOKEN TOKEN", false)]
        [InlineData(null, "CODE TOKEN", false)]
        [InlineData(null, "ID_TOKEN", false)]
        [InlineData(null, "ID_TOKEN TOKEN", false)]
        [InlineData(null, "TOKEN", false)]
        public void IsQueryResponseMode_ReturnsExpectedResult(string mode, string type, bool result)
        {
            // Arrange
            var request = new OpenIdConnectRequest();
            request.ResponseMode = mode;
            request.ResponseType = type;

            // Act and assert
            Assert.Equal(result, request.IsQueryResponseMode());
        }

        [Theory]
        [InlineData(null, false)]
        [InlineData("unknown", false)]
        [InlineData("query", false)]
        [InlineData("fragment", false)]
        [InlineData("form_post", true)]
        [InlineData("form_post ", false)]
        [InlineData(" form_post", false)]
        [InlineData(" form_post ", false)]
        [InlineData("QUERY", false)]
        [InlineData("FRAGMENT", false)]
        [InlineData("FORM_POST", false)]
        public void IsFormPostResponseMode_ReturnsExpectedResult(string mode, bool result)
        {
            // Arrange
            var request = new OpenIdConnectRequest();
            request.ResponseMode = mode;

            // Act and assert
            Assert.Equal(result, request.IsFormPostResponseMode());
        }

        [Theory]
        [InlineData(null, false)]
        [InlineData("unknown", false)]
        [InlineData("authorization_code", true)]
        [InlineData("authorization_code ", false)]
        [InlineData(" authorization_code", false)]
        [InlineData(" authorization_code ", false)]
        [InlineData("client_credentials", false)]
        [InlineData("password", false)]
        [InlineData("refresh_token", false)]
        [InlineData("AUTHORIZATION_CODE", false)]
        [InlineData("CLIENT_CREDENTIALS", false)]
        [InlineData("PASSWORD", false)]
        [InlineData("REFRESH_TOKEN", false)]
        public void IsAuthorizationCodeGrantType_ReturnsExpectedResult(string type, bool result)
        {
            // Arrange
            var request = new OpenIdConnectRequest();
            request.GrantType = type;

            // Act and assert
            Assert.Equal(result, request.IsAuthorizationCodeGrantType());
        }

        [Theory]
        [InlineData(null, false)]
        [InlineData("unknown", false)]
        [InlineData("authorization_code", false)]
        [InlineData("client_credentials", true)]
        [InlineData("client_credentials ", false)]
        [InlineData(" client_credentials", false)]
        [InlineData(" client_credentials ", false)]
        [InlineData("password", false)]
        [InlineData("refresh_token", false)]
        [InlineData("AUTHORIZATION_CODE", false)]
        [InlineData("CLIENT_CREDENTIALS", false)]
        [InlineData("PASSWORD", false)]
        [InlineData("REFRESH_TOKEN", false)]
        public void IsClientCredentialsGrantType_ReturnsExpectedResult(string type, bool result)
        {
            // Arrange
            var request = new OpenIdConnectRequest();
            request.GrantType = type;

            // Act and assert
            Assert.Equal(result, request.IsClientCredentialsGrantType());
        }

        [Theory]
        [InlineData(null, false)]
        [InlineData("unknown", false)]
        [InlineData("authorization_code", false)]
        [InlineData("client_credentials", false)]
        [InlineData("password", true)]
        [InlineData("password ", false)]
        [InlineData(" password", false)]
        [InlineData(" password ", false)]
        [InlineData("refresh_token", false)]
        [InlineData("AUTHORIZATION_CODE", false)]
        [InlineData("CLIENT_CREDENTIALS", false)]
        [InlineData("PASSWORD", false)]
        [InlineData("REFRESH_TOKEN", false)]
        public void IsPasswordGrantType_ReturnsExpectedResult(string type, bool result)
        {
            // Arrange
            var request = new OpenIdConnectRequest();
            request.GrantType = type;

            // Act and assert
            Assert.Equal(result, request.IsPasswordGrantType());
        }

        [Theory]
        [InlineData(null, false)]
        [InlineData("unknown", false)]
        [InlineData("authorization_code", false)]
        [InlineData("client_credentials", false)]
        [InlineData("password", false)]
        [InlineData("refresh_token", true)]
        [InlineData("refresh_token ", false)]
        [InlineData(" refresh_token", false)]
        [InlineData(" refresh_token ", false)]
        [InlineData("AUTHORIZATION_CODE", false)]
        [InlineData("CLIENT_CREDENTIALS", false)]
        [InlineData("PASSWORD", false)]
        [InlineData("REFRESH_TOKEN", false)]
        public void IsRefreshTokenGrantType_ReturnsExpectedResult(string type, bool result)
        {
            // Arrange
            var request = new OpenIdConnectRequest();
            request.GrantType = type;

            // Act and assert
            Assert.Equal(result, request.IsRefreshTokenGrantType());
        }
    }
}
