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
using Microsoft.AspNetCore.Authentication;
using Xunit;

namespace AspNet.Security.OpenIdConnect.Extensions.Tests
{
    public class OpenIdConnectExtensionsTests
    {
        [Fact]
        public void GetDestinations_ThrowsAnExceptionForNullClaim()
        {
            // Arrange
            var claim = (Claim) null;

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(delegate
            {
                claim.GetDestinations();
            });

            Assert.Equal("claim", exception.ParamName);
        }

        [Theory]
        [InlineData(null, new string[0])]
        [InlineData("", new string[0])]
        [InlineData("[]", new string[0])]
        [InlineData(@"[""id_token""]", new[] { "id_token" })]
        [InlineData(@"[""access_token"",""id_token""]", new[] { "access_token", "id_token" })]
        [InlineData(@"[""access_token"",""access_token"",""id_token""]", new[] { "access_token", "id_token" })]
        [InlineData(@"[""access_token"",""ACCESS_TOKEN"",""id_token""]", new[] { "access_token", "id_token" })]
        public void GetDestinations_ReturnsExpectedDestinations(string destination, string[] destinations)
        {
            // Arrange
            var claim = new Claim(OpenIdConnectConstants.Claims.Name, "Bob le Bricoleur");
            claim.Properties[OpenIdConnectConstants.Properties.Destinations] = destination;

            // Act and assert
            Assert.Equal(destinations, claim.GetDestinations());
        }

        [Fact]
        public void SetDestinations_ThrowsAnExceptionForNullTicket()
        {
            // Arrange
            var claim = (Claim) null;

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(delegate
            {
                claim.SetDestinations();
            });

            Assert.Equal("claim", exception.ParamName);
        }

        [Theory]
        [InlineData(null)]
        [InlineData(new object[] { new string[0] })]
        public void SetDestinations_RemovesPropertyForEmptyArray(string[] destinations)
        {
            // Arrange
            var claim = new Claim(OpenIdConnectConstants.Claims.Name, "Bob le Bricoleur");

            // Act
            claim.SetDestinations(destinations);

            // Assert
            Assert.Equal(0, claim.Properties.Count);
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        public void SetDestinations_ThrowsAnExceptionForNullOrEmptyDestinations(string destination)
        {
            // Arrange
            var claim = new Claim(OpenIdConnectConstants.Claims.Name, "Bob le Bricoleur");

            // Act and assert
            var exception = Assert.Throws<ArgumentException>(() => claim.SetDestinations(destination));

            Assert.Equal("destinations", exception.ParamName);
            Assert.StartsWith("Destinations cannot be null or empty.", exception.Message);
        }

        [Theory]
        [InlineData(new[] { "access_token" }, @"[""access_token""]")]
        [InlineData(new[] { "access_token", "id_token" }, @"[""access_token"",""id_token""]")]
        [InlineData(new[] { "access_token", "access_token", "id_token" }, @"[""access_token"",""id_token""]")]
        [InlineData(new[] { "access_token", "ACCESS_TOKEN", "id_token" }, @"[""access_token"",""id_token""]")]
        public void SetDestinations_SetsAppropriateDestinations(string[] destinations, string destination)
        {
            // Arrange
            var claim = new Claim(OpenIdConnectConstants.Claims.Name, "Bob le Bricoleur");

            // Act
            claim.SetDestinations(destinations);

            // Assert
            Assert.Equal(destination, claim.Properties[OpenIdConnectConstants.Properties.Destinations]);
        }

        [Fact]
        public void Clone_ThrowsAnExceptionForNullIdentity()
        {
            // Arrange
            var identity = (ClaimsIdentity) null;

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(delegate
            {
                identity.Clone(claim => true);
            });

            Assert.Equal("identity", exception.ParamName);
        }

        [Fact]
        public void Clone_ReturnsDifferentInstance()
        {
            // Arrange
            var identity = new ClaimsIdentity();
            identity.AddClaim(new Claim(OpenIdConnectConstants.Claims.Name, "Bob le Bricoleur"));

            // Act
            var clone = identity.Clone(claim => claim.Type == OpenIdConnectConstants.Claims.Name);
            clone.AddClaim(new Claim("clone_claim", "value"));

            // Assert
            Assert.NotSame(identity, clone);
            Assert.Null(identity.FindFirst("clone_claim"));
        }

        [Fact]
        public void Clone_ExcludesUnwantedClaims()
        {
            // Arrange
            var identity = new ClaimsIdentity();
            identity.AddClaim(new Claim(OpenIdConnectConstants.Claims.Name, "Bob le Bricoleur"));
            identity.AddClaim(new Claim(OpenIdConnectConstants.Claims.Subject, "D8F1A010-BD46-4F8F-AD4E-05582307F8F4"));

            // Act
            var clone = identity.Clone(claim => claim.Type == OpenIdConnectConstants.Claims.Name);

            // Assert
            Assert.Single(clone.Claims);
            Assert.Null(clone.FindFirst(OpenIdConnectConstants.Claims.Subject));
            Assert.Equal("Bob le Bricoleur", clone.FindFirst(OpenIdConnectConstants.Claims.Name).Value);
        }

        [Fact]
        public void Clone_ExcludesUnwantedClaimsFromActor()
        {
            // Arrange
            var identity = new ClaimsIdentity();
            identity.Actor = new ClaimsIdentity();
            identity.Actor.AddClaim(new Claim(OpenIdConnectConstants.Claims.Name, "Bob le Bricoleur"));
            identity.Actor.AddClaim(new Claim(OpenIdConnectConstants.Claims.Subject, "D8F1A010-BD46-4F8F-AD4E-05582307F8F4"));

            // Act
            var clone = identity.Clone(claim => claim.Type == OpenIdConnectConstants.Claims.Name);

            // Assert
            Assert.Single(clone.Actor.Claims);
            Assert.Null(clone.Actor.FindFirst(OpenIdConnectConstants.Claims.Subject));
            Assert.Equal("Bob le Bricoleur", clone.Actor.FindFirst(OpenIdConnectConstants.Claims.Name).Value);
        }

        [Fact]
        public void Clone_ExcludesUnwantedClaimsFromIdentities()
        {
            // Arrange
            var identity = new ClaimsIdentity();
            identity.AddClaim(new Claim(OpenIdConnectConstants.Claims.Name, "Bob le Bricoleur"));
            identity.AddClaim(new Claim(OpenIdConnectConstants.Claims.Subject, "D8F1A010-BD46-4F8F-AD4E-05582307F8F4"));

            var principal = new ClaimsPrincipal(identity);

            // Act
            var clone = principal.Clone(claim => claim.Type == OpenIdConnectConstants.Claims.Name);

            // Assert
            Assert.Single(clone.Claims);
            Assert.Null(clone.FindFirst(OpenIdConnectConstants.Claims.Subject));
            Assert.Equal("Bob le Bricoleur", clone.FindFirst(OpenIdConnectConstants.Claims.Name).Value);
        }

        [Fact]
        public void AddClaim_ThrowsAnExceptionForNullIdentity()
        {
            // Arrange
            var identity = (ClaimsIdentity) null;

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(delegate
            {
                identity.AddClaim(OpenIdConnectConstants.Claims.Name, "Bob le Bricoleur");
            });

            Assert.Equal("identity", exception.ParamName);
        }

        [Fact]
        public void AddClaim_SetsAppropriateClaim()
        {
            // Arrange
            var identity = new ClaimsIdentity();

            // Act
            identity.AddClaim(OpenIdConnectConstants.Claims.Name, "Bob le Bricoleur");

            // Assert
            Assert.Equal("Bob le Bricoleur", identity.FindFirst(OpenIdConnectConstants.Claims.Name).Value);
        }

        [Theory]
        [InlineData(new[] { "access_token" }, @"[""access_token""]")]
        [InlineData(new[] { "access_token", "id_token" }, @"[""access_token"",""id_token""]")]
        [InlineData(new[] { "access_token", "access_token", "id_token" }, @"[""access_token"",""id_token""]")]
        [InlineData(new[] { "access_token", "ACCESS_TOKEN", "id_token" }, @"[""access_token"",""id_token""]")]
        public void AddClaim_SetsAppropriateDestinations(string[] destinations, string destination)
        {
            // Arrange
            var identity = new ClaimsIdentity();

            // Act
            identity.AddClaim(OpenIdConnectConstants.Claims.Name, "Bob le Bricoleur", destinations);

            var claim = identity.FindFirst(OpenIdConnectConstants.Claims.Name);

            // Assert
            Assert.Equal("Bob le Bricoleur", claim.Value);
            Assert.Equal(destination, claim.Properties[OpenIdConnectConstants.Properties.Destinations]);
        }

        [Fact]
        public void GetClaim_ThrowsAnExceptionForNullIdentity()
        {
            // Arrange
            var identity = (ClaimsIdentity) null;

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(delegate
            {
                identity.GetClaim(OpenIdConnectConstants.Claims.Name);
            });

            Assert.Equal("identity", exception.ParamName);
        }

        [Fact]
        public void GetClaim_ReturnsNullForMissingClaims()
        {
            // Arrange
            var identity = new ClaimsIdentity();
            var principal = new ClaimsPrincipal();

            // Act and assert
            Assert.Null(identity.GetClaim(OpenIdConnectConstants.Claims.Name));
            Assert.Null(principal.GetClaim(OpenIdConnectConstants.Claims.Name));
        }

        [Fact]
        public void GetClaim_ReturnsAppropriateResult()
        {
            // Arrange
            var identity = new ClaimsIdentity();
            var principal = new ClaimsPrincipal(identity);

            identity.AddClaim(OpenIdConnectConstants.Claims.Name, "Bob le Bricoleur");

            // Act and assert
            Assert.Equal("Bob le Bricoleur", identity.GetClaim(OpenIdConnectConstants.Claims.Name));
            Assert.Equal("Bob le Bricoleur", principal.GetClaim(OpenIdConnectConstants.Claims.Name));
        }

        [Fact]
        public void Copy_ThrowsAnExceptionForNullProperties()
        {
            // Arrange
            var properties = (AuthenticationProperties) null;

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(delegate
            {
                properties.Copy();
            });

            Assert.Equal("properties", exception.ParamName);
        }

        [Fact]
        public void Copy_ReturnsIdenticalProperties()
        {
            // Arrange
            var properties = new AuthenticationProperties();
            properties.SetProperty("property", "value");

            // Act
            var copy = properties.Copy();

            // Assert
            Assert.Equal(properties.Items, copy.Items);
        }

        [Fact]
        public void Copy_ThrowsAnExceptionForNullTicket()
        {
            // Arrange
            var ticket = (AuthenticationTicket) null;

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(delegate
            {
                ticket.Copy();
            });

            Assert.Equal("ticket", exception.ParamName);
        }

        [Fact]
        public void Copy_ReturnsIdenticalTicket()
        {
            // Arrange
            var identity = new ClaimsIdentity();
            identity.AddClaim(new Claim(OpenIdConnectConstants.Claims.Name, "Bob le Bricoleur"));

            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(identity),
                new AuthenticationProperties(),
                nameof(AuthenticationTicket));

            ticket.SetProperty("property", "value");

            // Act
            var copy = ticket.Copy();

            // Assert
            Assert.Equal(ticket.AuthenticationScheme, copy.AuthenticationScheme);
            Assert.Equal("Bob le Bricoleur", copy.Principal.FindFirst(OpenIdConnectConstants.Claims.Name).Value);
            Assert.Equal(ticket.Properties.Items, copy.Properties.Items);
        }

        [Fact]
        public void Copy_ReturnsDifferentPropertiesInstance()
        {
            // Arrange
            var properties = new AuthenticationProperties();
            properties.SetProperty("property", "value");

            // Act
            var copy = properties.Copy();
            copy.SetProperty("clone_property", "value");

            // Assert
            Assert.NotSame(properties, copy);
            Assert.NotEqual(properties.Items, copy.Items);
        }

        [Fact]
        public void Copy_ReturnsDifferentTicketInstance()
        {
            // Arrange
            var identity = new ClaimsIdentity();
            identity.AddClaim(new Claim(OpenIdConnectConstants.Claims.Name, "Bob le Bricoleur"));

            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(identity),
                new AuthenticationProperties(),
                nameof(AuthenticationTicket));

            ticket.SetProperty("property", "value");

            // Act
            var copy = ticket.Copy();
            copy.Principal.Identities.First().AddClaim(new Claim("clone_claim", "value"));
            copy.SetProperty("clone_property", "value");

            // Assert
            Assert.NotSame(ticket, copy);
            Assert.Null(ticket.Principal.FindFirst("clone_claim"));
            Assert.NotEqual(ticket.Properties.Items, copy.Properties.Items);
        }

        [Fact]
        public void GetProperty_ThrowsAnExceptionForNullTicket()
        {
            // Arrange
            var ticket = (AuthenticationTicket) null;

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(delegate
            {
                ticket.GetProperty("property");
            });

            Assert.Equal("ticket", exception.ParamName);
        }

        [Fact]
        public void GetProperty_ReturnsNullForMissingProperty()
        {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(),
                new AuthenticationProperties(),
                nameof(AuthenticationTicket));

            // Act and assert
            Assert.Null(ticket.GetProperty("property"));
            Assert.Null(ticket.Properties.GetProperty("property"));
        }

        [Fact]
        public void GetProperty_ReturnsAppropriateResult()
        {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(),
                new AuthenticationProperties(),
                nameof(AuthenticationTicket));

            ticket.Properties.Items["property"] = "value";

            // Act and assert
            Assert.Equal("value", ticket.GetProperty("property"));
            Assert.Equal("value", ticket.Properties.GetProperty("property"));
        }

        [Fact]
        public void GetProperty_IsCaseSensitive()
        {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(),
                new AuthenticationProperties(),
                nameof(AuthenticationTicket));

            ticket.Properties.Items["property"] = "value";

            // Act and assert
            Assert.Null(ticket.GetProperty("PROPERTY"));
            Assert.Null(ticket.Properties.GetProperty("PROPERTY"));
        }

        [Fact]
        public void GetAudiences_ThrowsAnExceptionForNullTicket()
        {
            // Arrange
            var ticket = (AuthenticationTicket) null;

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(delegate
            {
                ticket.GetAudiences();
            });

            Assert.Equal("ticket", exception.ParamName);
        }

        [Theory]
        [InlineData(null, new string[0])]
        [InlineData("", new string[0])]
        [InlineData("[]", new string[0])]
        [InlineData(@"[""fabrikam""]", new[] { "fabrikam" })]
        [InlineData(@"[""fabrikam"",""contoso""]", new[] { "fabrikam", "contoso" })]
        [InlineData(@"[""fabrikam"",""fabrikam"",""contoso""]", new[] { "fabrikam", "contoso" })]
        [InlineData(@"[""fabrikam"",""FABRIKAM"",""contoso""]", new[] { "fabrikam", "FABRIKAM", "contoso" })]
        public void GetAudiences_ReturnsExpectedAudiences(string audience, string[] audiences)
        {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(),
                new AuthenticationProperties(),
                nameof(AuthenticationTicket));

            ticket.Properties.Items[OpenIdConnectConstants.Properties.Audiences] = audience;

            // Act and assert
            Assert.Equal(audiences, ticket.GetAudiences());
        }

        [Fact]
        public void GetPresenters_ThrowsAnExceptionForNullTicket()
        {
            // Arrange
            var ticket = (AuthenticationTicket) null;

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(delegate
            {
                ticket.GetPresenters();
            });

            Assert.Equal("ticket", exception.ParamName);
        }

        [Theory]
        [InlineData(null, new string[0])]
        [InlineData("", new string[0])]
        [InlineData("[]", new string[0])]
        [InlineData(@"[""fabrikam""]", new[] { "fabrikam" })]
        [InlineData(@"[""fabrikam"",""contoso""]", new[] { "fabrikam", "contoso" })]
        [InlineData(@"[""fabrikam"",""fabrikam"",""contoso""]", new[] { "fabrikam", "contoso" })]
        [InlineData(@"[""fabrikam"",""FABRIKAM"",""contoso""]", new[] { "fabrikam", "FABRIKAM", "contoso" })]
        public void GetPresenters_ReturnsExpectedPresenters(string presenter, string[] presenters)
        {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(),
                new AuthenticationProperties(),
                nameof(AuthenticationTicket));

            ticket.Properties.Items[OpenIdConnectConstants.Properties.Presenters] = presenter;

            // Act and assert
            Assert.Equal(presenters, ticket.GetPresenters());
        }

        [Fact]
        public void GetResources_ThrowsAnExceptionForNullTicket()
        {
            // Arrange
            var ticket = (AuthenticationTicket) null;

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(delegate
            {
                ticket.GetResources();
            });

            Assert.Equal("ticket", exception.ParamName);
        }

        [Theory]
        [InlineData(null, new string[0])]
        [InlineData("", new string[0])]
        [InlineData("[]", new string[0])]
        [InlineData(@"[""fabrikam""]", new[] { "fabrikam" })]
        [InlineData(@"[""fabrikam"",""contoso""]", new[] { "fabrikam", "contoso" })]
        [InlineData(@"[""fabrikam"",""fabrikam"",""contoso""]", new[] { "fabrikam", "contoso" })]
        [InlineData(@"[""fabrikam"",""FABRIKAM"",""contoso""]", new[] { "fabrikam", "FABRIKAM", "contoso" })]
        public void GetResources_ReturnsExpectedResources(string resource, string[] resources)
        {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(),
                new AuthenticationProperties(),
                nameof(AuthenticationTicket));

            ticket.Properties.Items[OpenIdConnectConstants.Properties.Resources] = resource;

            // Act and assert
            Assert.Equal(resources, ticket.GetResources());
        }

        [Fact]
        public void GetScopes_ThrowsAnExceptionForNullTicket()
        {
            // Arrange
            var ticket = (AuthenticationTicket) null;

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(delegate
            {
                ticket.GetScopes();
            });

            Assert.Equal("ticket", exception.ParamName);
        }

        [Theory]
        [InlineData(null, new string[0])]
        [InlineData("", new string[0])]
        [InlineData("[]", new string[0])]
        [InlineData(@"[""openid""]", new[] { "openid" })]
        [InlineData(@"[""openid"",""profile""]", new[] { "openid", "profile" })]
        [InlineData(@"[""openid"",""openid"",""profile""]", new[] { "openid", "profile" })]
        [InlineData(@"[""openid"",""OPENID"",""profile""]", new[] { "openid", "OPENID", "profile" })]
        public void GetScopes_ReturnsExpectedScopes(string scope, string[] scopes)
        {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(),
                new AuthenticationProperties(),
                nameof(AuthenticationTicket));

            ticket.Properties.Items[OpenIdConnectConstants.Properties.Scopes] = scope;

            // Act and assert
            Assert.Equal(scopes, ticket.GetScopes());
        }

        [Fact]
        public void GetAccessTokenLifetime_ThrowsAnExceptionForNullTicket()
        {
            // Arrange
            var ticket = (AuthenticationTicket) null;

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(delegate
            {
                ticket.GetAccessTokenLifetime();
            });

            Assert.Equal("ticket", exception.ParamName);
        }

        [Theory]
        [InlineData(null)]
        [InlineData("42.00:00:00")]
        public void GetAccessTokenLifetime_ReturnsExpectedResult(string lifetime)
        {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(),
                new AuthenticationProperties(),
                nameof(AuthenticationTicket));

            ticket.Properties.Items[OpenIdConnectConstants.Properties.AccessTokenLifetime] = lifetime;

            // Act and assert
            Assert.Equal(lifetime, ticket.GetAccessTokenLifetime()?.ToString("c", CultureInfo.InvariantCulture));
        }

        [Fact]
        public void GetAuthorizationCodeLifetime_ThrowsAnExceptionForNullTicket()
        {
            // Arrange
            var ticket = (AuthenticationTicket) null;

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(delegate
            {
                ticket.GetAuthorizationCodeLifetime();
            });

            Assert.Equal("ticket", exception.ParamName);
        }

        [Theory]
        [InlineData(null)]
        [InlineData("42.00:00:00")]
        public void GetAuthorizationCodeLifetime_ReturnsExpectedResult(string lifetime)
        {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(),
                new AuthenticationProperties(),
                nameof(AuthenticationTicket));

            ticket.Properties.Items[OpenIdConnectConstants.Properties.AuthorizationCodeLifetime] = lifetime;

            // Act and assert
            Assert.Equal(lifetime, ticket.GetAuthorizationCodeLifetime()?.ToString("c", CultureInfo.InvariantCulture));
        }

        [Fact]
        public void GetIdentityTokenLifetime_ThrowsAnExceptionForNullTicket()
        {
            // Arrange
            var ticket = (AuthenticationTicket) null;

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(delegate
            {
                ticket.GetIdentityTokenLifetime();
            });

            Assert.Equal("ticket", exception.ParamName);
        }

        [Theory]
        [InlineData(null)]
        [InlineData("42.00:00:00")]
        public void GetIdentityTokenLifetime_ReturnsExpectedResult(string lifetime)
        {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(),
                new AuthenticationProperties(),
                nameof(AuthenticationTicket));

            ticket.Properties.Items[OpenIdConnectConstants.Properties.IdentityTokenLifetime] = lifetime;

            // Act and assert
            Assert.Equal(lifetime, ticket.GetIdentityTokenLifetime()?.ToString("c", CultureInfo.InvariantCulture));
        }

        [Fact]
        public void GetRefreshTokenLifetime_ThrowsAnExceptionForNullTicket()
        {
            // Arrange
            var ticket = (AuthenticationTicket) null;

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(delegate
            {
                ticket.GetRefreshTokenLifetime();
            });

            Assert.Equal("ticket", exception.ParamName);
        }

        [Theory]
        [InlineData(null)]
        [InlineData("42.00:00:00")]
        public void GetRefreshTokenLifetime_ReturnsExpectedResult(string lifetime)
        {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(),
                new AuthenticationProperties(),
                nameof(AuthenticationTicket));

            ticket.Properties.Items[OpenIdConnectConstants.Properties.RefreshTokenLifetime] = lifetime;

            // Act and assert
            Assert.Equal(lifetime, ticket.GetRefreshTokenLifetime()?.ToString("c", CultureInfo.InvariantCulture));
        }

        [Fact]
        public void GetTokenId_ThrowsAnExceptionForNullTicket()
        {
            // Arrange
            var ticket = (AuthenticationTicket) null;

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(delegate
            {
                ticket.GetTokenId();
            });

            Assert.Equal("ticket", exception.ParamName);
        }

        [Theory]
        [InlineData(null)]
        [InlineData("identifier")]
        public void GetTokenId_ReturnsExpectedResult(string identifier)
        {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(),
                new AuthenticationProperties(),
                nameof(AuthenticationTicket));

            ticket.Properties.Items[OpenIdConnectConstants.Properties.TokenId] = identifier;

            // Act and assert
            Assert.Equal(identifier, ticket.GetTokenId());
        }

        [Fact]
        public void GetTokenUsage_ThrowsAnExceptionForNullTicket()
        {
            // Arrange
            var ticket = (AuthenticationTicket) null;

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(delegate
            {
                ticket.GetTokenUsage();
            });

            Assert.Equal("ticket", exception.ParamName);
        }

        [Theory]
        [InlineData(null)]
        [InlineData("access_token")]
        public void GetTokenUsage_ReturnsExpectedResult(string usage)
        {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(),
                new AuthenticationProperties(),
                nameof(AuthenticationTicket));

            ticket.Properties.Items[OpenIdConnectConstants.Properties.TokenUsage] = usage;

            // Act and assert
            Assert.Equal(usage, ticket.GetTokenUsage());
        }

        [Fact]
        public void HasProperty_ThrowsAnExceptionForNullTicket()
        {
            // Arrange
            var ticket = (AuthenticationTicket) null;

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(delegate
            {
                ticket.HasProperty("property");
            });

            Assert.Equal("ticket", exception.ParamName);
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        public void HasProperty_ThrowsAnExceptionForNullOrEmptyProperty(string property)
        {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(),
                new AuthenticationProperties(),
                nameof(AuthenticationTicket));

            // Act and assert
            var exception = Assert.Throws<ArgumentException>(delegate
            {
                ticket.HasProperty(property);
            });

            Assert.Equal("property", exception.ParamName);
            Assert.StartsWith("The property name cannot be null or empty.", exception.Message);
        }

        [Theory]
        [InlineData(null, false)]
        [InlineData("value", true)]
        public void HasProperty_ReturnsExpectedResult(string value, bool result)
        {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(),
                new AuthenticationProperties(),
                nameof(AuthenticationTicket));

            ticket.Properties.Items["property"] = value;

            // Act and assert
            Assert.Equal(result, ticket.HasProperty("property"));
            Assert.Equal(result, ticket.Properties.HasProperty("property"));
        }

        [Fact]
        public void HasAudience_ThrowsAnExceptionForNullTicket()
        {
            // Arrange
            var ticket = (AuthenticationTicket) null;

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(delegate
            {
                ticket.HasAudience("Fabrikam");
            });

            Assert.Equal("ticket", exception.ParamName);
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        public void HasAudience_ThrowsAnExceptionForNullOrEmptyAudience(string audience)
        {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(),
                new AuthenticationProperties(),
                nameof(AuthenticationTicket));

            // Act and assert
            var exception = Assert.Throws<ArgumentException>(delegate
            {
                ticket.HasAudience(audience);
            });

            Assert.Equal("audience", exception.ParamName);
            Assert.StartsWith("The audience cannot be null or empty.", exception.Message);
        }

        [Theory]
        [InlineData(null, false)]
        [InlineData("", false)]
        [InlineData("[]", false)]
        [InlineData(@"[""fabrikam""]", true)]
        public void HasAudience_ReturnsExpectedResult(string audience, bool result)
        {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(),
                new AuthenticationProperties(),
                nameof(AuthenticationTicket));

            ticket.Properties.Items[OpenIdConnectConstants.Properties.Audiences] = audience;

            // Act and assert
            Assert.Equal(result, ticket.HasAudience());
        }

        [Theory]
        [InlineData(null, false)]
        [InlineData("", false)]
        [InlineData("[]", false)]
        [InlineData(@"[""contoso""]", false)]
        [InlineData(@"[""contoso"",""fabrikam""]", true)]
        [InlineData(@"[""fabrikam""]", true)]
        [InlineData(@"[""fabrikam"",""contoso""]", true)]
        [InlineData(@"[""CONTOSO""]", false)]
        [InlineData(@"[""CONTOSO"",""FABRIKAM""]", false)]
        [InlineData(@"[""FABRIKAM""]", false)]
        [InlineData(@"[""FABRIKAM"",""CONTOSO""]", false)]
        public void HasAudience_ReturnsAppropriateResult(string audience, bool result)
        {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(),
                new AuthenticationProperties(),
                nameof(AuthenticationTicket));

            ticket.Properties.Items[OpenIdConnectConstants.Properties.Audiences] = audience;

            // Act and assert
            Assert.Equal(result, ticket.HasAudience("fabrikam"));
        }

        [Fact]
        public void HasPresenter_ThrowsAnExceptionForNullTicket()
        {
            // Arrange
            var ticket = (AuthenticationTicket) null;

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(delegate
            {
                ticket.HasPresenter("Fabrikam");
            });

            Assert.Equal("ticket", exception.ParamName);
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        public void HasPresenter_ThrowsAnExceptionForNullOrEmptyPresenter(string presenter)
        {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(),
                new AuthenticationProperties(),
                nameof(AuthenticationTicket));

            // Act and assert
            var exception = Assert.Throws<ArgumentException>(delegate
            {
                ticket.HasPresenter(presenter);
            });

            Assert.Equal("presenter", exception.ParamName);
            Assert.StartsWith("The presenter cannot be null or empty.", exception.Message);
        }

        [Theory]
        [InlineData(null, false)]
        [InlineData("", false)]
        [InlineData("[]", false)]
        [InlineData(@"[""fabrikam""]", true)]
        public void HasPresenter_ReturnsExpectedResult(string presenter, bool result)
        {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(),
                new AuthenticationProperties(),
                nameof(AuthenticationTicket));

            ticket.Properties.Items[OpenIdConnectConstants.Properties.Presenters] = presenter;

            // Act and assert
            Assert.Equal(result, ticket.HasPresenter());
        }

        [Theory]
        [InlineData(null, false)]
        [InlineData("", false)]
        [InlineData("[]", false)]
        [InlineData(@"[""contoso""]", false)]
        [InlineData(@"[""contoso"",""fabrikam""]", true)]
        [InlineData(@"[""fabrikam""]", true)]
        [InlineData(@"[""fabrikam"",""contoso""]", true)]
        [InlineData(@"[""CONTOSO""]", false)]
        [InlineData(@"[""CONTOSO"",""FABRIKAM""]", false)]
        [InlineData(@"[""FABRIKAM""]", false)]
        [InlineData(@"[""FABRIKAM"",""CONTOSO""]", false)]
        public void HasPresenter_ReturnsAppropriateResult(string presenter, bool result)
        {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(),
                new AuthenticationProperties(),
                nameof(AuthenticationTicket));

            ticket.Properties.Items[OpenIdConnectConstants.Properties.Presenters] = presenter;

            // Act and assert
            Assert.Equal(result, ticket.HasPresenter("fabrikam"));
        }

        [Fact]
        public void HasResource_ThrowsAnExceptionForNullTicket()
        {
            // Arrange
            var ticket = (AuthenticationTicket) null;

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(delegate
            {
                ticket.HasResource("Fabrikam");
            });

            Assert.Equal("ticket", exception.ParamName);
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        public void HasResource_ThrowsAnExceptionForNullOrEmptyResource(string resource)
        {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(),
                new AuthenticationProperties(),
                nameof(AuthenticationTicket));

            // Act and assert
            var exception = Assert.Throws<ArgumentException>(delegate
            {
                ticket.HasResource(resource);
            });

            Assert.Equal("resource", exception.ParamName);
            Assert.StartsWith("The resource cannot be null or empty.", exception.Message);
        }

        [Theory]
        [InlineData(null, false)]
        [InlineData("", false)]
        [InlineData("[]", false)]
        [InlineData(@"[""fabrikam""]", true)]
        public void HasResource_ReturnsExpectedResult(string resource, bool result)
        {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(),
                new AuthenticationProperties(),
                nameof(AuthenticationTicket));

            ticket.Properties.Items[OpenIdConnectConstants.Properties.Resources] = resource;

            // Act and assert
            Assert.Equal(result, ticket.HasResource());
        }

        [Theory]
        [InlineData(null, false)]
        [InlineData("", false)]
        [InlineData("[]", false)]
        [InlineData(@"[""contoso""]", false)]
        [InlineData(@"[""contoso"",""fabrikam""]", true)]
        [InlineData(@"[""fabrikam""]", true)]
        [InlineData(@"[""fabrikam"",""contoso""]", true)]
        [InlineData(@"[""CONTOSO""]", false)]
        [InlineData(@"[""CONTOSO"",""FABRIKAM""]", false)]
        [InlineData(@"[""FABRIKAM""]", false)]
        [InlineData(@"[""FABRIKAM"",""CONTOSO""]", false)]
        public void HasResource_ReturnsAppropriateResult(string resource, bool result)
        {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(),
                new AuthenticationProperties(),
                nameof(AuthenticationTicket));

            ticket.Properties.Items[OpenIdConnectConstants.Properties.Resources] = resource;

            // Act and assert
            Assert.Equal(result, ticket.HasResource("fabrikam"));
        }

        [Fact]
        public void HasScope_ThrowsAnExceptionForNullTicket()
        {
            // Arrange
            var ticket = (AuthenticationTicket) null;

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(delegate
            {
                ticket.HasScope(OpenIdConnectConstants.Scopes.OpenId);
            });

            Assert.Equal("ticket", exception.ParamName);
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        public void HasScope_ThrowsAnExceptionForNullOrEmptyScope(string scope)
        {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(),
                new AuthenticationProperties(),
                nameof(AuthenticationTicket));

            // Act and assert
            var exception = Assert.Throws<ArgumentException>(delegate
            {
                ticket.HasScope(scope);
            });

            Assert.Equal("scope", exception.ParamName);
            Assert.StartsWith("The scope cannot be null or empty.", exception.Message);
        }

        [Theory]
        [InlineData(null, false)]
        [InlineData("", false)]
        [InlineData("[]", false)]
        [InlineData(@"[""openid""]", true)]
        public void HasScope_ReturnsExpectedResult(string scope, bool result)
        {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(),
                new AuthenticationProperties(),
                nameof(AuthenticationTicket));

            ticket.Properties.Items[OpenIdConnectConstants.Properties.Scopes] = scope;

            // Act and assert
            Assert.Equal(result, ticket.HasScope());
        }

        [Theory]
        [InlineData(null, false)]
        [InlineData("", false)]
        [InlineData("[]", false)]
        [InlineData(@"[""profile""]", false)]
        [InlineData(@"[""profile"",""openid""]", true)]
        [InlineData(@"[""openid""]", true)]
        [InlineData(@"[""openid"",""profile""]", true)]
        [InlineData(@"[""PROFILE""]", false)]
        [InlineData(@"[""PROFILE"",""OPENID""]", false)]
        [InlineData(@"[""OPENID""]", false)]
        [InlineData(@"[""OPENID"",""PROFILE""]", false)]
        public void HasScope_ReturnsAppropriateResult(string scope, bool result)
        {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(),
                new AuthenticationProperties(),
                nameof(AuthenticationTicket));

            ticket.Properties.Items[OpenIdConnectConstants.Properties.Scopes] = scope;

            // Act and assert
            Assert.Equal(result, ticket.HasScope(OpenIdConnectConstants.Scopes.OpenId));
        }

        [Fact]
        public void IsConfidential_ThrowsAnExceptionForNullTicket()
        {
            // Arrange
            var ticket = (AuthenticationTicket) null;

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(delegate
            {
                ticket.IsConfidential();
            });

            Assert.Equal("ticket", exception.ParamName);
        }

        [Theory]
        [InlineData(null, false)]
        [InlineData("unknown", false)]
        [InlineData(OpenIdConnectConstants.ConfidentialityLevels.Private, true)]
        [InlineData(OpenIdConnectConstants.ConfidentialityLevels.Public, false)]
        public void IsConfidential_ReturnsExpectedResult(string level, bool result)
        {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(),
                new AuthenticationProperties(),
                nameof(AuthenticationTicket));

            ticket.Properties.Items[OpenIdConnectConstants.Properties.ConfidentialityLevel] = level;

            // Act and assert
            Assert.Equal(result, ticket.IsConfidential());
        }

        [Fact]
        public void IsAccessToken_ThrowsAnExceptionForNullTicket()
        {
            // Arrange
            var ticket = (AuthenticationTicket) null;

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(delegate
            {
                ticket.IsAccessToken();
            });

            Assert.Equal("ticket", exception.ParamName);
        }

        [Theory]
        [InlineData(null, false)]
        [InlineData("unknown", false)]
        [InlineData(OpenIdConnectConstants.TokenUsages.AccessToken, true)]
        [InlineData(OpenIdConnectConstants.TokenUsages.AuthorizationCode, false)]
        [InlineData(OpenIdConnectConstants.TokenUsages.IdToken, false)]
        [InlineData(OpenIdConnectConstants.TokenUsages.RefreshToken, false)]
        public void IsAccessToken_ReturnsExpectedResult(string usage, bool result)
        {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(),
                new AuthenticationProperties(),
                nameof(AuthenticationTicket));

            ticket.Properties.Items[OpenIdConnectConstants.Properties.TokenUsage] = usage;

            // Act and assert
            Assert.Equal(result, ticket.IsAccessToken());
        }

        [Fact]
        public void IsAuthorizationCode_ThrowsAnExceptionForNullTicket()
        {
            // Arrange
            var ticket = (AuthenticationTicket) null;

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(delegate
            {
                ticket.IsConfidential();
            });

            Assert.Equal("ticket", exception.ParamName);
        }

        [Theory]
        [InlineData(null, false)]
        [InlineData("unknown", false)]
        [InlineData(OpenIdConnectConstants.TokenUsages.AccessToken, false)]
        [InlineData(OpenIdConnectConstants.TokenUsages.AuthorizationCode, true)]
        [InlineData(OpenIdConnectConstants.TokenUsages.IdToken, false)]
        [InlineData(OpenIdConnectConstants.TokenUsages.RefreshToken, false)]
        public void IsAuthorizationCode_ReturnsExpectedResult(string usage, bool result)
        {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(),
                new AuthenticationProperties(),
                nameof(AuthenticationTicket));

            ticket.Properties.Items[OpenIdConnectConstants.Properties.TokenUsage] = usage;

            // Act and assert
            Assert.Equal(result, ticket.IsAuthorizationCode());
        }

        [Fact]
        public void IsIdentityToken_ThrowsAnExceptionForNullTicket()
        {
            // Arrange
            var ticket = (AuthenticationTicket) null;

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(delegate
            {
                ticket.IsConfidential();
            });

            Assert.Equal("ticket", exception.ParamName);
        }

        [Theory]
        [InlineData(null, false)]
        [InlineData("unknown", false)]
        [InlineData(OpenIdConnectConstants.TokenUsages.AccessToken, false)]
        [InlineData(OpenIdConnectConstants.TokenUsages.AuthorizationCode, false)]
        [InlineData(OpenIdConnectConstants.TokenUsages.IdToken, true)]
        [InlineData(OpenIdConnectConstants.TokenUsages.RefreshToken, false)]
        public void IsIdentityToken_ReturnsExpectedResult(string usage, bool result)
        {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(),
                new AuthenticationProperties(),
                nameof(AuthenticationTicket));

            ticket.Properties.Items[OpenIdConnectConstants.Properties.TokenUsage] = usage;

            // Act and assert
            Assert.Equal(result, ticket.IsIdentityToken());
        }

        [Fact]
        public void IsRefreshToken_ThrowsAnExceptionForNullTicket()
        {
            // Arrange
            var ticket = (AuthenticationTicket) null;

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(delegate
            {
                ticket.IsConfidential();
            });

            Assert.Equal("ticket", exception.ParamName);
        }

        [Theory]
        [InlineData(null, false)]
        [InlineData("unknown", false)]
        [InlineData(OpenIdConnectConstants.TokenUsages.AccessToken, false)]
        [InlineData(OpenIdConnectConstants.TokenUsages.AuthorizationCode, false)]
        [InlineData(OpenIdConnectConstants.TokenUsages.IdToken, false)]
        [InlineData(OpenIdConnectConstants.TokenUsages.RefreshToken, true)]
        public void IsRefreshToken_ReturnsExpectedResult(string usage, bool result)
        {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(),
                new AuthenticationProperties(),
                nameof(AuthenticationTicket));

            ticket.Properties.Items[OpenIdConnectConstants.Properties.TokenUsage] = usage;

            // Act and assert
            Assert.Equal(result, ticket.IsRefreshToken());
        }

        [Fact]
        public void AddProperty_ThrowsAnExceptionForNullTicket()
        {
            // Arrange
            var ticket = (AuthenticationTicket) null;

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(delegate
            {
                ticket.AddProperty("property", "value");
            });

            Assert.Equal("ticket", exception.ParamName);
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        public void AddProperty_ThrowsAnExceptionForNullOrEmptyProperty(string property)
        {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(),
                new AuthenticationProperties(),
                nameof(AuthenticationTicket));

            // Act and assert
            var exception = Assert.Throws<ArgumentException>(delegate
            {
                ticket.AddProperty(property, "value");
            });

            Assert.Equal("property", exception.ParamName);
            Assert.StartsWith("The property name cannot be null or empty.", exception.Message);
        }

        [Fact]
        public void AddProperty_AddsExpectedProperty()
        {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(),
                new AuthenticationProperties(),
                nameof(AuthenticationTicket));

            // Act
            ticket.AddProperty("property", "value");

            // Assert
            Assert.Equal("value", ticket.GetProperty("property"));
        }

        [Fact]
        public void RemoveProperty_ThrowsAnExceptionForNullTicket()
        {
            // Arrange
            var ticket = (AuthenticationTicket) null;

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(delegate
            {
                ticket.RemoveProperty("property");
            });

            Assert.Equal("ticket", exception.ParamName);
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        public void RemoveProperty_ThrowsAnExceptionForNullOrEmptyProperty(string property)
        {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(),
                new AuthenticationProperties(),
                nameof(AuthenticationTicket));

            // Act and assert
            var exception = Assert.Throws<ArgumentException>(delegate
            {
                ticket.RemoveProperty(property);
            });

            Assert.Equal("property", exception.ParamName);
            Assert.StartsWith("The property name cannot be null or empty.", exception.Message);
        }

        [Fact]
        public void RemoveProperty_RemovesProperty()
        {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(),
                new AuthenticationProperties(),
                nameof(AuthenticationTicket));

            ticket.AddProperty("property", "value");

            // Act
            ticket.RemoveProperty("property");

            // Assert
            Assert.Null(ticket.GetProperty("property"));
        }

        [Fact]
        public void SetProperty_ThrowsAnExceptionForNullTicket()
        {
            // Arrange
            var ticket = (AuthenticationTicket) null;

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(delegate
            {
                ticket.SetProperty("property", "value");
            });

            Assert.Equal("ticket", exception.ParamName);
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        public void SetProperty_ThrowsAnExceptionForNullOrEmptyProperty(string property)
        {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(),
                new AuthenticationProperties(),
                nameof(AuthenticationTicket));

            // Act and assert
            var exception = Assert.Throws<ArgumentException>(delegate
            {
                ticket.SetProperty(property, "value");
            });

            Assert.Equal("property", exception.ParamName);
            Assert.StartsWith("The property name cannot be null or empty.", exception.Message);
        }

        [Fact]
        public void SetProperty_AddsExpectedProperty()
        {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(),
                new AuthenticationProperties(),
                nameof(AuthenticationTicket));

            // Act
            ticket.SetProperty("property", "value");

            // Assert
            Assert.Equal("value", ticket.GetProperty("property"));
        }

        [Fact]
        public void SetProperty_IsCaseSensitive()
        {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(),
                new AuthenticationProperties(),
                nameof(AuthenticationTicket));

            // Act
            ticket.SetProperty("PROPERTY", "value");

            // Assert
            Assert.Null(ticket.GetProperty("property"));
        }

        [Fact]
        public void SetProperty_RemovesEmptyProperty()
        {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(),
                new AuthenticationProperties(),
                nameof(AuthenticationTicket));

            // Act
            ticket.SetProperty("property", string.Empty);

            // Assert
            Assert.Null(ticket.GetProperty("property"));
        }

        [Fact]
        public void SetAudiences_ThrowsAnExceptionForNullTicket()
        {
            // Arrange
            var ticket = (AuthenticationTicket) null;

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(delegate
            {
                ticket.SetAudiences();
            });

            Assert.Equal("ticket", exception.ParamName);
        }

        [Theory]
        [InlineData(new string[0], null)]
        [InlineData(new[] { "fabrikam" }, @"[""fabrikam""]")]
        [InlineData(new[] { "fabrikam", "contoso" }, @"[""fabrikam"",""contoso""]")]
        [InlineData(new[] { "fabrikam", "fabrikam", "contoso" }, @"[""fabrikam"",""contoso""]")]
        [InlineData(new[] { "fabrikam", "FABRIKAM", "contoso" }, @"[""fabrikam"",""FABRIKAM"",""contoso""]")]
        public void SetAudiences_AddsAudiences(string[] audiences, string audience)
        {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(),
                new AuthenticationProperties(),
                nameof(AuthenticationTicket));

            // Act
            ticket.SetAudiences(audiences);

            // Assert
            Assert.Equal(audience, ticket.GetProperty(OpenIdConnectConstants.Properties.Audiences));
        }

        [Fact]
        public void SetPresenters_ThrowsAnExceptionForNullTicket()
        {
            // Arrange
            var ticket = (AuthenticationTicket) null;

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(delegate
            {
                ticket.SetPresenters();
            });

            Assert.Equal("ticket", exception.ParamName);
        }

        [Theory]
        [InlineData(new string[0], null)]
        [InlineData(new[] { "fabrikam" }, @"[""fabrikam""]")]
        [InlineData(new[] { "fabrikam", "contoso" }, @"[""fabrikam"",""contoso""]")]
        [InlineData(new[] { "fabrikam", "fabrikam", "contoso" }, @"[""fabrikam"",""contoso""]")]
        [InlineData(new[] { "fabrikam", "FABRIKAM", "contoso" }, @"[""fabrikam"",""FABRIKAM"",""contoso""]")]
        public void SetPresenters_AddsPresenters(string[] presenters, string presenter)
        {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(),
                new AuthenticationProperties(),
                nameof(AuthenticationTicket));

            // Act
            ticket.SetPresenters(presenters);

            // Assert
            Assert.Equal(presenter, ticket.GetProperty(OpenIdConnectConstants.Properties.Presenters));
        }

        [Fact]
        public void SetResources_ThrowsAnExceptionForNullTicket()
        {
            // Arrange
            var ticket = (AuthenticationTicket) null;

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(delegate
            {
                ticket.SetResources();
            });

            Assert.Equal("ticket", exception.ParamName);
        }

        [Theory]
        [InlineData(new string[0], null)]
        [InlineData(new[] { "fabrikam" }, @"[""fabrikam""]")]
        [InlineData(new[] { "fabrikam", "contoso" }, @"[""fabrikam"",""contoso""]")]
        [InlineData(new[] { "fabrikam", "fabrikam", "contoso" }, @"[""fabrikam"",""contoso""]")]
        [InlineData(new[] { "fabrikam", "FABRIKAM", "contoso" }, @"[""fabrikam"",""FABRIKAM"",""contoso""]")]
        public void SetResources_AddsResources(string[] resources, string resource)
        {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(),
                new AuthenticationProperties(),
                nameof(AuthenticationTicket));

            // Act
            ticket.SetResources(resources);

            // Assert
            Assert.Equal(resource, ticket.GetProperty(OpenIdConnectConstants.Properties.Resources));
        }

        [Fact]
        public void SetScopes_ThrowsAnExceptionForNullTicket()
        {
            // Arrange
            var ticket = (AuthenticationTicket) null;

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(delegate
            {
                ticket.SetScopes();
            });

            Assert.Equal("ticket", exception.ParamName);
        }

        [Theory]
        [InlineData(new string[0], null)]
        [InlineData(new[] { "openid" }, @"[""openid""]")]
        [InlineData(new[] { "openid", "profile" }, @"[""openid"",""profile""]")]
        [InlineData(new[] { "openid", "openid", "profile" }, @"[""openid"",""profile""]")]
        [InlineData(new[] { "openid", "OPENID", "profile" }, @"[""openid"",""OPENID"",""profile""]")]
        public void SetScopes_AddsScopes(string[] scopes, string scope)
        {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(),
                new AuthenticationProperties(),
                nameof(AuthenticationTicket));

            // Act
            ticket.SetScopes(scopes);

            // Assert
            Assert.Equal(scope, ticket.GetProperty(OpenIdConnectConstants.Properties.Scopes));
        }

        [Fact]
        public void SetAccessTokenLifetime_ThrowsAnExceptionForNullTicket()
        {
            // Arrange
            var ticket = (AuthenticationTicket) null;

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(delegate
            {
                ticket.SetAccessTokenLifetime(null);
            });

            Assert.Equal("ticket", exception.ParamName);
        }

        [Theory]
        [InlineData(null)]
        [InlineData("42.00:00:00")]
        public void SetAccessTokenLifetime_AddsLifetime(string lifetime)
        {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(),
                new AuthenticationProperties(),
                nameof(AuthenticationTicket));

            // Act
            ticket.SetAccessTokenLifetime(lifetime != null ? (TimeSpan?) TimeSpan.ParseExact(lifetime, "c", CultureInfo.InvariantCulture) : null);

            // Assert
            Assert.Equal(lifetime, ticket.GetProperty(OpenIdConnectConstants.Properties.AccessTokenLifetime));
        }

        [Fact]
        public void SetAuthorizationCodeLifetime_ThrowsAnExceptionForNullTicket()
        {
            // Arrange
            var ticket = (AuthenticationTicket) null;

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(delegate
            {
                ticket.SetAuthorizationCodeLifetime(null);
            });

            Assert.Equal("ticket", exception.ParamName);
        }

        [Theory]
        [InlineData(null)]
        [InlineData("42.00:00:00")]
        public void SetAuthorizationCodeLifetime_AddsLifetime(string lifetime)
        {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(),
                new AuthenticationProperties(),
                nameof(AuthenticationTicket));

            // Act
            ticket.SetAuthorizationCodeLifetime(lifetime != null ? (TimeSpan?) TimeSpan.ParseExact(lifetime, "c", CultureInfo.InvariantCulture) : null);

            // Assert
            Assert.Equal(lifetime, ticket.GetProperty(OpenIdConnectConstants.Properties.AuthorizationCodeLifetime));
        }

        [Fact]
        public void SetIdentityTokenLifetime_ThrowsAnExceptionForNullTicket()
        {
            // Arrange
            var ticket = (AuthenticationTicket) null;

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(delegate
            {
                ticket.SetIdentityTokenLifetime(null);
            });

            Assert.Equal("ticket", exception.ParamName);
        }

        [Theory]
        [InlineData(null)]
        [InlineData("42.00:00:00")]
        public void SetIdentityTokenLifetime_AddsLifetime(string lifetime)
        {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(),
                new AuthenticationProperties(),
                nameof(AuthenticationTicket));

            // Act
            ticket.SetIdentityTokenLifetime(lifetime != null ? (TimeSpan?) TimeSpan.ParseExact(lifetime, "c", CultureInfo.InvariantCulture) : null);

            // Assert
            Assert.Equal(lifetime, ticket.GetProperty(OpenIdConnectConstants.Properties.IdentityTokenLifetime));
        }

        [Fact]
        public void SetRefreshTokenLifetime_ThrowsAnExceptionForNullTicket()
        {
            // Arrange
            var ticket = (AuthenticationTicket) null;

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(delegate
            {
                ticket.SetRefreshTokenLifetime(null);
            });

            Assert.Equal("ticket", exception.ParamName);
        }

        [Theory]
        [InlineData(null)]
        [InlineData("42.00:00:00")]
        public void SetRefreshTokenLifetime_AddsLifetime(string lifetime)
        {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(),
                new AuthenticationProperties(),
                nameof(AuthenticationTicket));

            // Act
            ticket.SetRefreshTokenLifetime(lifetime != null ? (TimeSpan?) TimeSpan.ParseExact(lifetime, "c", CultureInfo.InvariantCulture) : null);

            // Assert
            Assert.Equal(lifetime, ticket.GetProperty(OpenIdConnectConstants.Properties.RefreshTokenLifetime));
        }

        [Fact]
        public void SetTokenId_ThrowsAnExceptionForNullTicket()
        {
            // Arrange
            var ticket = (AuthenticationTicket) null;

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(delegate
            {
                ticket.SetTokenId(null);
            });

            Assert.Equal("ticket", exception.ParamName);
        }

        [Theory]
        [InlineData(null)]
        [InlineData("identifier")]
        public void SetTokenId_AddsScopes(string identifier)
        {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(),
                new AuthenticationProperties(),
                nameof(AuthenticationTicket));

            // Act
            ticket.SetTokenId(identifier);

            // Assert
            Assert.Equal(identifier, ticket.GetProperty(OpenIdConnectConstants.Properties.TokenId));
        }

        [Fact]
        public void SetTokenUsage_ThrowsAnExceptionForNullTicket()
        {
            // Arrange
            var ticket = (AuthenticationTicket) null;

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(delegate
            {
                ticket.SetTokenUsage(null);
            });

            Assert.Equal("ticket", exception.ParamName);
        }

        [Theory]
        [InlineData(null)]
        [InlineData("usage")]
        public void SetTokenUsage_AddsScopes(string usage)
        {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(),
                new AuthenticationProperties(),
                nameof(AuthenticationTicket));

            // Act
            ticket.SetTokenUsage(usage);

            // Assert
            Assert.Equal(usage, ticket.GetProperty(OpenIdConnectConstants.Properties.TokenUsage));
        }
    }
}
