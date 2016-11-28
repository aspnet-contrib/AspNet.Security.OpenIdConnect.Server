/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.Globalization;
using System.Linq;
using System.Security.Claims;
using AspNet.Security.OpenIdConnect.Primitives;
using Microsoft.Owin.Security;
using Xunit;

namespace Owin.Security.OpenIdConnect.Extensions.Tests {
    public class OpenIdConnectExtensionsTests {
        [Theory]
        [InlineData(null, new string[0])]
        [InlineData("id_token", new[] { "id_token" })]
        [InlineData("id_token ", new[] { "id_token" })]
        [InlineData(" id_token", new[] { "id_token" })]
        [InlineData(" id_token ", new[] { "id_token" })]
        [InlineData("access_token id_token", new[] { "access_token", "id_token" })]
        [InlineData("access_token id_token ", new[] { "access_token", "id_token" })]
        [InlineData(" access_token id_token", new[] { "access_token", "id_token" })]
        [InlineData(" access_token id_token ", new[] { "access_token", "id_token" })]
        [InlineData("access_token access_token id_token", new[] { "access_token", "id_token" })]
        [InlineData("access_token ACCESS_TOKEN id_token", new[] { "access_token", "id_token" })]
        public void GetDestinations_ReturnsExpectedDestinations(string destination, string[] destinations) {
            // Arrange
            var claim = new Claim(ClaimTypes.Name, "Bob le Bricoleur");
            claim.Properties[OpenIdConnectConstants.Properties.Destinations] = destination;

            // Act and assert
            Assert.Equal(destinations, claim.GetDestinations());
        }

        [Theory]
        [InlineData(null)]
        [InlineData(new object[] { new string[0] })]
        public void SetDestinations_RemovesPropertyForEmptyArray(string[] destinations) {
            // Arrange
            var claim = new Claim(ClaimTypes.Name, "Bob le Bricoleur");

            // Act
            claim.SetDestinations(destinations);

            // Assert
            Assert.Equal(0, claim.Properties.Count);
        }

        [Theory]
        [InlineData("destination ")]
        [InlineData(" destination")]
        [InlineData(" destination ")]
        public void SetDestinations_ThrowsForInvalidDestinations(string destination) {
            // Arrange
            var claim = new Claim(ClaimTypes.Name, "Bob le Bricoleur");

            // Act and assert
            var exception = Assert.Throws<ArgumentException>(() => claim.SetDestinations(destination));

            Assert.Equal(exception.ParamName, "destinations");
            Assert.StartsWith("Destinations cannot contain spaces.", exception.Message);
        }

        [Theory]
        [InlineData(new[] { "access_token" }, "access_token")]
        [InlineData(new[] { "access_token", "id_token" }, "access_token id_token")]
        [InlineData(new[] { "access_token", "access_token", "id_token" }, "access_token id_token")]
        [InlineData(new[] { "access_token", "ACCESS_TOKEN", "id_token" }, "access_token id_token")]
        public void SetDestinations_SetsAppropriateDestinations(string[] destinations, string destination) {
            // Arrange
            var claim = new Claim(ClaimTypes.Name, "Bob le Bricoleur");

            // Act
            claim.SetDestinations(destinations);

            // Assert
            Assert.Equal(destination, claim.Properties[OpenIdConnectConstants.Properties.Destinations]);
        }

        [Fact]
        public void Clone_ReturnsDifferentInstance() {
            // Arrange
            var identity = new ClaimsIdentity();
            identity.AddClaim(new Claim(ClaimTypes.Name, "Bob le Bricoleur"));

            // Act
            var clone = identity.Clone(claim => claim.Type == ClaimTypes.Name);
            clone.AddClaim(new Claim("clone_claim", "value"));

            // Assert
            Assert.NotSame(identity, clone);
            Assert.Null(identity.FindFirst("clone_claim"));
        }

        [Fact]
        public void Clone_ExcludesUnwantedClaims() {
            // Arrange
            var identity = new ClaimsIdentity();
            identity.AddClaim(new Claim(ClaimTypes.Name, "Bob le Bricoleur"));
            identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, "D8F1A010-BD46-4F8F-AD4E-05582307F8F4"));

            // Act
            var clone = identity.Clone(claim => claim.Type == ClaimTypes.Name);

            // Assert
            Assert.Equal(1, clone.Claims.Count());
            Assert.Null(clone.FindFirst(ClaimTypes.NameIdentifier));
            Assert.Equal("Bob le Bricoleur", clone.FindFirst(ClaimTypes.Name).Value);
        }

        [Fact]
        public void Clone_ExcludesUnwantedClaimsFromActor() {
            // Arrange
            var identity = new ClaimsIdentity();
            identity.Actor = new ClaimsIdentity();
            identity.Actor.AddClaim(new Claim(ClaimTypes.Name, "Bob le Bricoleur"));
            identity.Actor.AddClaim(new Claim(ClaimTypes.NameIdentifier, "D8F1A010-BD46-4F8F-AD4E-05582307F8F4"));

            // Act
            var clone = identity.Clone(claim => claim.Type == ClaimTypes.Name);

            // Assert
            Assert.Equal(1, clone.Actor.Claims.Count());
            Assert.Null(clone.Actor.FindFirst(ClaimTypes.NameIdentifier));
            Assert.Equal("Bob le Bricoleur", clone.Actor.FindFirst(ClaimTypes.Name).Value);
        }

        [Fact]
        public void Clone_ExcludesUnwantedClaimsFromIdentities() {
            // Arrange
            var identity = new ClaimsIdentity();
            identity.AddClaim(new Claim(ClaimTypes.Name, "Bob le Bricoleur"));
            identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, "D8F1A010-BD46-4F8F-AD4E-05582307F8F4"));

            var principal = new ClaimsPrincipal(identity);

            // Act
            var clone = principal.Clone(claim => claim.Type == ClaimTypes.Name);

            // Assert
            Assert.Equal(1, clone.Claims.Count());
            Assert.Null(clone.FindFirst(ClaimTypes.NameIdentifier));
            Assert.Equal("Bob le Bricoleur", clone.FindFirst(ClaimTypes.Name).Value);
        }

        [Fact]
        public void AddClaim_SetsAppropriateClaim() {
            // Arrange
            var identity = new ClaimsIdentity();

            // Act
            identity.AddClaim(ClaimTypes.Name, "Bob le Bricoleur");

            // Assert
            Assert.Equal("Bob le Bricoleur", identity.FindFirst(ClaimTypes.Name).Value);
        }

        [Theory]
        [InlineData(new[] { "access_token" }, "access_token")]
        [InlineData(new[] { "access_token", "id_token" }, "access_token id_token")]
        [InlineData(new[] { "access_token", "access_token", "id_token" }, "access_token id_token")]
        [InlineData(new[] { "access_token", "ACCESS_TOKEN", "id_token" }, "access_token id_token")]
        public void AddClaim_SetsAppropriateDestinations(string[] destinations, string destination) {
            // Arrange
            var identity = new ClaimsIdentity();

            // Act
            identity.AddClaim(ClaimTypes.Name, "Bob le Bricoleur", destinations);

            var claim = identity.FindFirst(ClaimTypes.Name);

            // Assert
            Assert.Equal("Bob le Bricoleur", claim.Value);
            Assert.Equal(destination, claim.Properties[OpenIdConnectConstants.Properties.Destinations]);
        }

        [Fact]
        public void GetClaim_ReturnsNullForMissingClaims() {
            // Arrange
            var identity = new ClaimsIdentity();
            var principal = new ClaimsPrincipal();

            // Act and assert
            Assert.Null(identity.GetClaim(ClaimTypes.Name));
            Assert.Null(principal.GetClaim(ClaimTypes.Name));
        }

        [Fact]
        public void GetClaim_ReturnsAppropriateResult() {
            // Arrange
            var identity = new ClaimsIdentity();
            var principal = new ClaimsPrincipal(identity);

            identity.AddClaim(ClaimTypes.Name, "Bob le Bricoleur");

            // Act and assert
            Assert.Equal("Bob le Bricoleur", identity.GetClaim(ClaimTypes.Name));
            Assert.Equal("Bob le Bricoleur", principal.GetClaim(ClaimTypes.Name));
        }

        [Fact]
        public void Copy_ReturnsIdenticalProperties() {
            // Arrange
            var properties = new AuthenticationProperties();
            properties.SetProperty("property", "value");

            // Act
            var copy = properties.Copy();

            // Assert
            Assert.Equal(properties.Dictionary, copy.Dictionary);
        }

        [Fact]
        public void Copy_ReturnsIdenticalTicket() {
            // Arrange
            var identity = new ClaimsIdentity();
            identity.AddClaim(new Claim(ClaimTypes.Name, "Bob le Bricoleur"));

            var ticket = new AuthenticationTicket(identity, new AuthenticationProperties());
            ticket.SetProperty("property", "value");

            // Act
            var copy = ticket.Copy();

            // Assert
            Assert.Equal("Bob le Bricoleur", copy.Identity.FindFirst(ClaimTypes.Name).Value);
            Assert.Equal(ticket.Properties.Dictionary, copy.Properties.Dictionary);
        }

        [Fact]
        public void Copy_ReturnsDifferentPropertiesInstance() {
            // Arrange
            var properties = new AuthenticationProperties();
            properties.SetProperty("property", "value");

            // Act
            var copy = properties.Copy();
            copy.SetProperty("clone_property", "value");

            // Assert
            Assert.NotSame(properties, copy);
            Assert.NotEqual(properties.Dictionary, copy.Dictionary);
        }

        [Fact]
        public void Copy_ReturnsDifferentTicketInstance() {
            // Arrange
            var identity = new ClaimsIdentity();
            identity.AddClaim(new Claim(ClaimTypes.Name, "Bob le Bricoleur"));

            var ticket = new AuthenticationTicket(identity, new AuthenticationProperties());
            ticket.SetProperty("property", "value");

            // Act
            var copy = ticket.Copy();
            copy.Identity.AddClaim(new Claim("clone_claim", "value"));
            copy.SetProperty("clone_property", "value");

            // Assert
            Assert.NotSame(ticket, copy);
            Assert.Null(ticket.Identity.FindFirst("clone_claim"));
            Assert.NotEqual(ticket.Properties.Dictionary, copy.Properties.Dictionary);
        }

        [Fact]
        public void GetProperty_ReturnsNullForMissingProperty() {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsIdentity(),
                new AuthenticationProperties());

            // Act and assert
            Assert.Null(ticket.GetProperty("property"));
            Assert.Null(ticket.Properties.GetProperty("property"));
        }

        [Fact]
        public void GetProperty_ReturnsAppropriateResult() {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsIdentity(),
                new AuthenticationProperties());

            ticket.Properties.Dictionary["property"] = "value";

            // Act and assert
            Assert.Equal("value", ticket.GetProperty("property"));
            Assert.Equal("value", ticket.Properties.GetProperty("property"));
        }

        [Fact]
        public void GetProperty_IsCaseSensitive() {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsIdentity(),
                new AuthenticationProperties());

            ticket.Properties.Dictionary["property"] = "value";

            // Act and assert
            Assert.Null(ticket.GetProperty("PROPERTY"));
            Assert.Null(ticket.Properties.GetProperty("PROPERTY"));
        }

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
        public void GetAudiences_ReturnsExpectedAudiences(string audience, string[] audiences) {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsIdentity(),
                new AuthenticationProperties());

            ticket.Properties.Dictionary[OpenIdConnectConstants.Properties.Audiences] = audience;

            // Act and assert
            Assert.Equal(audiences, ticket.GetAudiences());
        }

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
        public void GetPresenters_ReturnsExpectedPresenters(string presenter, string[] presenters) {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsIdentity(),
                new AuthenticationProperties());

            ticket.Properties.Dictionary[OpenIdConnectConstants.Properties.Presenters] = presenter;

            // Act and assert
            Assert.Equal(presenters, ticket.GetPresenters());
        }

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
        public void GetResources_ReturnsExpectedResources(string resource, string[] resources) {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsIdentity(),
                new AuthenticationProperties());

            ticket.Properties.Dictionary[OpenIdConnectConstants.Properties.Resources] = resource;

            // Act and assert
            Assert.Equal(resources, ticket.GetResources());
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
        public void GetScopes_ReturnsExpectedScopes(string scope, string[] scopes) {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsIdentity(),
                new AuthenticationProperties());

            ticket.Properties.Dictionary[OpenIdConnectConstants.Properties.Scopes] = scope;

            // Act and assert
            Assert.Equal(scopes, ticket.GetScopes());
        }

        [Theory]
        [InlineData(null)]
        [InlineData("42.00:00:00")]
        public void GetAccessTokenLifetime_ReturnsExpectedResult(string lifetime) {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsIdentity(),
                new AuthenticationProperties());

            ticket.Properties.Dictionary[OpenIdConnectConstants.Properties.AccessTokenLifetime] = lifetime;

            // Act and assert
            Assert.Equal(lifetime, ticket.GetAccessTokenLifetime()?.ToString("c", CultureInfo.InvariantCulture));
        }

        [Theory]
        [InlineData(null)]
        [InlineData("42.00:00:00")]
        public void GetAuthorizationCodeLifetime_ReturnsExpectedResult(string lifetime) {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsIdentity(),
                new AuthenticationProperties());

            ticket.Properties.Dictionary[OpenIdConnectConstants.Properties.AuthorizationCodeLifetime] = lifetime;

            // Act and assert
            Assert.Equal(lifetime, ticket.GetAuthorizationCodeLifetime()?.ToString("c", CultureInfo.InvariantCulture));
        }

        [Theory]
        [InlineData(null)]
        [InlineData("42.00:00:00")]
        public void GetIdentityTokenLifetime_ReturnsExpectedResult(string lifetime) {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsIdentity(),
                new AuthenticationProperties());

            ticket.Properties.Dictionary[OpenIdConnectConstants.Properties.IdentityTokenLifetime] = lifetime;

            // Act and assert
            Assert.Equal(lifetime, ticket.GetIdentityTokenLifetime()?.ToString("c", CultureInfo.InvariantCulture));
        }

        [Theory]
        [InlineData(null)]
        [InlineData("42.00:00:00")]
        public void GetRefreshTokenLifetime_ReturnsExpectedResult(string lifetime) {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsIdentity(),
                new AuthenticationProperties());

            ticket.Properties.Dictionary[OpenIdConnectConstants.Properties.RefreshTokenLifetime] = lifetime;

            // Act and assert
            Assert.Equal(lifetime, ticket.GetRefreshTokenLifetime()?.ToString("c", CultureInfo.InvariantCulture));
        }

        [Theory]
        [InlineData(null)]
        [InlineData("identifier")]
        public void GetTicketId_ReturnsExpectedResult(string identifier) {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsIdentity(),
                new AuthenticationProperties());

            ticket.Properties.Dictionary[OpenIdConnectConstants.Properties.TicketId] = identifier;

            // Act and assert
            Assert.Equal(identifier, ticket.GetTicketId());
        }

        [Theory]
        [InlineData(null)]
        [InlineData("access_token")]
        public void GetUsage_ReturnsExpectedResult(string usage) {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsIdentity(),
                new AuthenticationProperties());

            ticket.Properties.Dictionary[OpenIdConnectConstants.Properties.Usage] = usage;

            // Act and assert
            Assert.Equal(usage, ticket.GetUsage());
        }

        [Theory]
        [InlineData(null, false)]
        [InlineData("value", true)]
        public void HasProperty_ReturnsExpectedResult(string value, bool result) {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsIdentity(),
                new AuthenticationProperties());

            ticket.Properties.Dictionary["property"] = value;

            // Act and assert
            Assert.Equal(result, ticket.HasProperty("property"));
            Assert.Equal(result, ticket.Properties.HasProperty("property"));
        }

        [Theory]
        [InlineData(null, false)]
        [InlineData("fabrikam", true)]
        public void HasAudience_ReturnsExpectedResult(string audience, bool result) {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsIdentity(),
                new AuthenticationProperties());

            ticket.Properties.Dictionary[OpenIdConnectConstants.Properties.Audiences] = audience;

            // Act and assert
            Assert.Equal(result, ticket.HasAudience());
        }

        [Theory]
        [InlineData(null, false)]
        [InlineData("contoso", false)]
        [InlineData("fabrikam", true)]
        [InlineData("fabrikam ", true)]
        [InlineData(" fabrikam", true)]
        [InlineData(" fabrikam ", true)]
        [InlineData("fabrikam contoso", true)]
        [InlineData("fabrikam contoso ", true)]
        [InlineData(" fabrikam contoso", true)]
        [InlineData(" fabrikam contoso ", true)]
        [InlineData(" fabrikam  contoso ", true)]
        [InlineData("CONTOSO", false)]
        [InlineData("FABRIKAM", false)]
        [InlineData("FABRIKAM ", false)]
        [InlineData(" FABRIKAM", false)]
        [InlineData(" FABRIKAM ", false)]
        [InlineData("FABRIKAM CONTOSO", false)]
        [InlineData("FABRIKAM CONTOSO ", false)]
        [InlineData(" FABRIKAM CONTOSO", false)]
        [InlineData(" FABRIKAM CONTOSO ", false)]
        [InlineData(" FABRIKAM  CONTOSO ", false)]
        public void HasAudience_ReturnsAppropriateResult(string audience, bool result) {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsIdentity(),
                new AuthenticationProperties());

            ticket.Properties.Dictionary[OpenIdConnectConstants.Properties.Audiences] = audience;

            // Act and assert
            Assert.Equal(result, ticket.HasAudience("fabrikam"));
        }

        [Theory]
        [InlineData(null, false)]
        [InlineData("fabrikam", true)]
        public void HasPresenter_ReturnsExpectedResult(string presenter, bool result) {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsIdentity(),
                new AuthenticationProperties());

            ticket.Properties.Dictionary[OpenIdConnectConstants.Properties.Presenters] = presenter;

            // Act and assert
            Assert.Equal(result, ticket.HasPresenter());
        }

        [Theory]
        [InlineData(null, false)]
        [InlineData("contoso", false)]
        [InlineData("fabrikam", true)]
        [InlineData("fabrikam ", true)]
        [InlineData(" fabrikam", true)]
        [InlineData(" fabrikam ", true)]
        [InlineData("fabrikam contoso", true)]
        [InlineData("fabrikam contoso ", true)]
        [InlineData(" fabrikam contoso", true)]
        [InlineData(" fabrikam contoso ", true)]
        [InlineData(" fabrikam  contoso ", true)]
        [InlineData("CONTOSO", false)]
        [InlineData("FABRIKAM", false)]
        [InlineData("FABRIKAM ", false)]
        [InlineData(" FABRIKAM", false)]
        [InlineData(" FABRIKAM ", false)]
        [InlineData("FABRIKAM CONTOSO", false)]
        [InlineData("FABRIKAM CONTOSO ", false)]
        [InlineData(" FABRIKAM CONTOSO", false)]
        [InlineData(" FABRIKAM CONTOSO ", false)]
        [InlineData(" FABRIKAM  CONTOSO ", false)]
        public void HasPresenter_ReturnsAppropriateResult(string presenter, bool result) {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsIdentity(),
                new AuthenticationProperties());

            ticket.Properties.Dictionary[OpenIdConnectConstants.Properties.Presenters] = presenter;

            // Act and assert
            Assert.Equal(result, ticket.HasPresenter("fabrikam"));
        }

        [Theory]
        [InlineData(null, false)]
        [InlineData("fabrikam", true)]
        public void HasResource_ReturnsExpectedResult(string resource, bool result) {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsIdentity(),
                new AuthenticationProperties());

            ticket.Properties.Dictionary[OpenIdConnectConstants.Properties.Resources] = resource;

            // Act and assert
            Assert.Equal(result, ticket.HasResource());
        }

        [Theory]
        [InlineData(null, false)]
        [InlineData("contoso", false)]
        [InlineData("fabrikam", true)]
        [InlineData("fabrikam ", true)]
        [InlineData(" fabrikam", true)]
        [InlineData(" fabrikam ", true)]
        [InlineData("fabrikam contoso", true)]
        [InlineData("fabrikam contoso ", true)]
        [InlineData(" fabrikam contoso", true)]
        [InlineData(" fabrikam contoso ", true)]
        [InlineData(" fabrikam  contoso ", true)]
        [InlineData("CONTOSO", false)]
        [InlineData("FABRIKAM", false)]
        [InlineData("FABRIKAM ", false)]
        [InlineData(" FABRIKAM", false)]
        [InlineData(" FABRIKAM ", false)]
        [InlineData("FABRIKAM CONTOSO", false)]
        [InlineData("FABRIKAM CONTOSO ", false)]
        [InlineData(" FABRIKAM CONTOSO", false)]
        [InlineData(" FABRIKAM CONTOSO ", false)]
        [InlineData(" FABRIKAM  CONTOSO ", false)]
        public void HasResource_ReturnsAppropriateResult(string resource, bool result) {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsIdentity(),
                new AuthenticationProperties());

            ticket.Properties.Dictionary[OpenIdConnectConstants.Properties.Resources] = resource;

            // Act and assert
            Assert.Equal(result, ticket.HasResource("fabrikam"));
        }

        [Theory]
        [InlineData(null, false)]
        [InlineData("fabrikam", true)]
        public void HasScope_ReturnsExpectedResult(string scope, bool result) {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsIdentity(),
                new AuthenticationProperties());

            ticket.Properties.Dictionary[OpenIdConnectConstants.Properties.Scopes] = scope;

            // Act and assert
            Assert.Equal(result, ticket.HasScope());
        }

        [Theory]
        [InlineData(null, false)]
        [InlineData("profile", false)]
        [InlineData("openid", true)]
        [InlineData("openid ", true)]
        [InlineData(" openid", true)]
        [InlineData(" openid ", true)]
        [InlineData("openid profile", true)]
        [InlineData("openid profile ", true)]
        [InlineData(" openid profile", true)]
        [InlineData(" openid profile ", true)]
        [InlineData(" openid  profile ", true)]
        [InlineData("PROFILE", false)]
        [InlineData("OPENID", false)]
        [InlineData("OPENID ", false)]
        [InlineData(" OPENID", false)]
        [InlineData(" OPENID ", false)]
        [InlineData("OPENID PROFILE", false)]
        [InlineData("OPENID PROFILE ", false)]
        [InlineData(" OPENID PROFILE", false)]
        [InlineData(" OPENID PROFILE ", false)]
        [InlineData(" OPENID  PROFILE ", false)]
        public void HasScope_ReturnsAppropriateResult(string scope, bool result) {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsIdentity(),
                new AuthenticationProperties());

            ticket.Properties.Dictionary[OpenIdConnectConstants.Properties.Scopes] = scope;

            // Act and assert
            Assert.Equal(result, ticket.HasScope(OpenIdConnectConstants.Scopes.OpenId));
        }

        [Theory]
        [InlineData(null, false)]
        [InlineData("unknown", false)]
        [InlineData(OpenIdConnectConstants.ConfidentialityLevels.Private, true)]
        [InlineData(OpenIdConnectConstants.ConfidentialityLevels.Public, false)]
        public void IsConfidential_ReturnsExpectedResult(string level, bool result) {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsIdentity(),
                new AuthenticationProperties());

            ticket.Properties.Dictionary[OpenIdConnectConstants.Properties.ConfidentialityLevel] = level;

            // Act and assert
            Assert.Equal(result, ticket.IsConfidential());
        }

        [Theory]
        [InlineData(null, false)]
        [InlineData("unknown", false)]
        [InlineData(OpenIdConnectConstants.Usages.AccessToken, true)]
        [InlineData(OpenIdConnectConstants.Usages.AuthorizationCode, false)]
        [InlineData(OpenIdConnectConstants.Usages.IdentityToken, false)]
        [InlineData(OpenIdConnectConstants.Usages.RefreshToken, false)]
        public void IsAccessToken_ReturnsExpectedResult(string usage, bool result) {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsIdentity(),
                new AuthenticationProperties());

            ticket.Properties.Dictionary[OpenIdConnectConstants.Properties.Usage] = usage;

            // Act and assert
            Assert.Equal(result, ticket.IsAccessToken());
        }

        [Theory]
        [InlineData(null, false)]
        [InlineData("unknown", false)]
        [InlineData(OpenIdConnectConstants.Usages.AccessToken, false)]
        [InlineData(OpenIdConnectConstants.Usages.AuthorizationCode, true)]
        [InlineData(OpenIdConnectConstants.Usages.IdentityToken, false)]
        [InlineData(OpenIdConnectConstants.Usages.RefreshToken, false)]
        public void IsAuthorizationCode_ReturnsExpectedResult(string usage, bool result) {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsIdentity(),
                new AuthenticationProperties());

            ticket.Properties.Dictionary[OpenIdConnectConstants.Properties.Usage] = usage;

            // Act and assert
            Assert.Equal(result, ticket.IsAuthorizationCode());
        }

        [Theory]
        [InlineData(null, false)]
        [InlineData("unknown", false)]
        [InlineData(OpenIdConnectConstants.Usages.AccessToken, false)]
        [InlineData(OpenIdConnectConstants.Usages.AuthorizationCode, false)]
        [InlineData(OpenIdConnectConstants.Usages.IdentityToken, true)]
        [InlineData(OpenIdConnectConstants.Usages.RefreshToken, false)]
        public void IsIdentityToken_ReturnsExpectedResult(string usage, bool result) {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsIdentity(),
                new AuthenticationProperties());

            ticket.Properties.Dictionary[OpenIdConnectConstants.Properties.Usage] = usage;

            // Act and assert
            Assert.Equal(result, ticket.IsIdentityToken());
        }

        [Theory]
        [InlineData(null, false)]
        [InlineData("unknown", false)]
        [InlineData(OpenIdConnectConstants.Usages.AccessToken, false)]
        [InlineData(OpenIdConnectConstants.Usages.AuthorizationCode, false)]
        [InlineData(OpenIdConnectConstants.Usages.IdentityToken, false)]
        [InlineData(OpenIdConnectConstants.Usages.RefreshToken, true)]
        public void IsRefreshToken_ReturnsExpectedResult(string usage, bool result) {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsIdentity(),
                new AuthenticationProperties());

            ticket.Properties.Dictionary[OpenIdConnectConstants.Properties.Usage] = usage;

            // Act and assert
            Assert.Equal(result, ticket.IsRefreshToken());
        }

        [Fact]
        public void SetProperty_AddsExpectedProperty() {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsIdentity(),
                new AuthenticationProperties());

            // Act
            ticket.SetProperty("property", "value");

            // Assert
            Assert.Equal("value", ticket.GetProperty("property"));
        }

        [Fact]
        public void SetProperty_IsCaseSensitive() {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsIdentity(),
                new AuthenticationProperties());

            // Act
            ticket.SetProperty("PROPERTY", "value");

            // Assert
            Assert.Null(ticket.GetProperty("property"));
        }

        [Fact]
        public void SetProperty_RemovesEmptyProperty() {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsIdentity(),
                new AuthenticationProperties());

            // Act
            ticket.SetProperty("property", string.Empty);

            // Assert
            Assert.Null(ticket.GetProperty("property"));
        }

        [Theory]
        [InlineData(new string[0], null)]
        [InlineData(new[] { "fabrikam" }, "fabrikam")]
        [InlineData(new[] { "fabrikam", "contoso" }, "fabrikam contoso")]
        [InlineData(new[] { "fabrikam", "fabrikam", "contoso" }, "fabrikam contoso")]
        [InlineData(new[] { "fabrikam", "FABRIKAM", "contoso" }, "fabrikam FABRIKAM contoso")]
        public void SetAudiences_AddsAudiences(string[] audiences, string audience) {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsIdentity(),
                new AuthenticationProperties());

            // Act
            ticket.SetAudiences(audiences);

            // Assert
            Assert.Equal(audience, ticket.GetProperty(OpenIdConnectConstants.Properties.Audiences));
        }

        [Theory]
        [InlineData(new string[0], null)]
        [InlineData(new[] { "fabrikam" }, "fabrikam")]
        [InlineData(new[] { "fabrikam", "contoso" }, "fabrikam contoso")]
        [InlineData(new[] { "fabrikam", "fabrikam", "contoso" }, "fabrikam contoso")]
        [InlineData(new[] { "fabrikam", "FABRIKAM", "contoso" }, "fabrikam FABRIKAM contoso")]
        public void SetPresenters_AddsPresenters(string[] presenters, string presenter) {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsIdentity(),
                new AuthenticationProperties());

            // Act
            ticket.SetPresenters(presenters);

            // Assert
            Assert.Equal(presenter, ticket.GetProperty(OpenIdConnectConstants.Properties.Presenters));
        }

        [Theory]
        [InlineData(new string[0], null)]
        [InlineData(new[] { "fabrikam" }, "fabrikam")]
        [InlineData(new[] { "fabrikam", "contoso" }, "fabrikam contoso")]
        [InlineData(new[] { "fabrikam", "fabrikam", "contoso" }, "fabrikam contoso")]
        [InlineData(new[] { "fabrikam", "FABRIKAM", "contoso" }, "fabrikam FABRIKAM contoso")]
        public void SetResources_AddsResources(string[] resources, string resource) {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsIdentity(),
                new AuthenticationProperties());

            // Act
            ticket.SetResources(resources);

            // Assert
            Assert.Equal(resource, ticket.GetProperty(OpenIdConnectConstants.Properties.Resources));
        }

        [Theory]
        [InlineData(new string[0], null)]
        [InlineData(new[] { "openid" }, "openid")]
        [InlineData(new[] { "openid", "profile" }, "openid profile")]
        [InlineData(new[] { "openid", "openid", "profile" }, "openid profile")]
        [InlineData(new[] { "openid", "OPENID", "profile" }, "openid OPENID profile")]
        public void SetScopes_AddsScopes(string[] scopes, string scope) {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsIdentity(),
                new AuthenticationProperties());

            // Act
            ticket.SetScopes(scopes);

            // Assert
            Assert.Equal(scope, ticket.GetProperty(OpenIdConnectConstants.Properties.Scopes));
        }

        [Theory]
        [InlineData(null)]
        [InlineData("42.00:00:00")]
        public void SetAccessTokenLifetime_AddsLifetime(string lifetime) {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsIdentity(),
                new AuthenticationProperties());

            // Act
            ticket.SetAccessTokenLifetime(lifetime != null ? (TimeSpan?) TimeSpan.ParseExact(lifetime, "c", CultureInfo.InvariantCulture) : null);

            // Assert
            Assert.Equal(lifetime, ticket.GetProperty(OpenIdConnectConstants.Properties.AccessTokenLifetime));
        }

        [Theory]
        [InlineData(null)]
        [InlineData("42.00:00:00")]
        public void SetAuthorizationCodeLifetime_AddsLifetime(string lifetime) {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsIdentity(),
                new AuthenticationProperties());

            // Act
            ticket.SetAuthorizationCodeLifetime(lifetime != null ? (TimeSpan?) TimeSpan.ParseExact(lifetime, "c", CultureInfo.InvariantCulture) : null);

            // Assert
            Assert.Equal(lifetime, ticket.GetProperty(OpenIdConnectConstants.Properties.AuthorizationCodeLifetime));
        }

        [Theory]
        [InlineData(null)]
        [InlineData("42.00:00:00")]
        public void SetIdentityTokenLifetime_AddsLifetime(string lifetime) {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsIdentity(),
                new AuthenticationProperties());

            // Act
            ticket.SetIdentityTokenLifetime(lifetime != null ? (TimeSpan?) TimeSpan.ParseExact(lifetime, "c", CultureInfo.InvariantCulture) : null);

            // Assert
            Assert.Equal(lifetime, ticket.GetProperty(OpenIdConnectConstants.Properties.IdentityTokenLifetime));
        }

        [Theory]
        [InlineData(null)]
        [InlineData("42.00:00:00")]
        public void SetRefreshTokenLifetime_AddsLifetime(string lifetime) {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsIdentity(),
                new AuthenticationProperties());

            // Act
            ticket.SetRefreshTokenLifetime(lifetime != null ? (TimeSpan?) TimeSpan.ParseExact(lifetime, "c", CultureInfo.InvariantCulture) : null);

            // Assert
            Assert.Equal(lifetime, ticket.GetProperty(OpenIdConnectConstants.Properties.RefreshTokenLifetime));
        }

        [Theory]
        [InlineData(null)]
        [InlineData("identifier")]
        public void SetTicketId_AddsScopes(string identifier) {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsIdentity(),
                new AuthenticationProperties());

            // Act
            ticket.SetTicketId(identifier);

            // Assert
            Assert.Equal(identifier, ticket.GetProperty(OpenIdConnectConstants.Properties.TicketId));
        }

        [Theory]
        [InlineData(null)]
        [InlineData("usage")]
        public void SetUsage_AddsScopes(string usage) {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsIdentity(),
                new AuthenticationProperties());

            // Act
            ticket.SetUsage(usage);

            // Assert
            Assert.Equal(usage, ticket.GetProperty(OpenIdConnectConstants.Properties.Usage));
        }
    }
}
