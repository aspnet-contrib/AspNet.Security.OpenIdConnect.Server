using System.Collections.Generic;
using System.Reflection;
using Newtonsoft.Json.Linq;
using Xunit;

namespace AspNet.Security.OpenIdConnect.Primitives.Tests {
    public class OpenIdConnectRequestTests {
        public static IEnumerable<object[]> Properties {
            get {
                yield return new object[] {
                    /* property: */ nameof(OpenIdConnectRequest.AccessToken),
                    /* name: */ OpenIdConnectConstants.Parameters.AccessToken,
                    /* value: */ "802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4"
                };

                yield return new object[] {
                    /* property: */ nameof(OpenIdConnectRequest.Assertion),
                    /* name: */ OpenIdConnectConstants.Parameters.Assertion,
                    /* value: */ "802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4"
                };

                yield return new object[] {
                    /* property: */ nameof(OpenIdConnectRequest.ClientAssertion),
                    /* name: */ OpenIdConnectConstants.Parameters.ClientAssertion,
                    /* value: */ "802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4"
                };

                yield return new object[] {
                    /* property: */ nameof(OpenIdConnectRequest.ClientAssertionType),
                    /* name: */ OpenIdConnectConstants.Parameters.ClientAssertionType,
                    /* value: */ "802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4"
                };

                yield return new object[] {
                    /* property: */ nameof(OpenIdConnectRequest.ClientId),
                    /* name: */ OpenIdConnectConstants.Parameters.ClientId,
                    /* value: */ "802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4"
                };

                yield return new object[] {
                    /* property: */ nameof(OpenIdConnectRequest.ClientSecret),
                    /* name: */ OpenIdConnectConstants.Parameters.ClientSecret,
                    /* value: */ "802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4"
                };

                yield return new object[] {
                    /* property: */ nameof(OpenIdConnectRequest.Code),
                    /* name: */ OpenIdConnectConstants.Parameters.Code,
                    /* value: */ "802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4"
                };

                yield return new object[] {
                    /* property: */ nameof(OpenIdConnectRequest.CodeChallenge),
                    /* name: */ OpenIdConnectConstants.Parameters.CodeChallenge,
                    /* value: */ "802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4"
                };

                yield return new object[] {
                    /* property: */ nameof(OpenIdConnectRequest.CodeChallengeMethod),
                    /* name: */ OpenIdConnectConstants.Parameters.CodeChallengeMethod,
                    /* value: */ "802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4"
                };

                yield return new object[] {
                    /* property: */ nameof(OpenIdConnectRequest.CodeVerifier),
                    /* name: */ OpenIdConnectConstants.Parameters.CodeVerifier,
                    /* value: */ "802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4"
                };

                yield return new object[] {
                    /* property: */ nameof(OpenIdConnectRequest.GrantType),
                    /* name: */ OpenIdConnectConstants.Parameters.GrantType,
                    /* value: */ "802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4"
                };

                yield return new object[] {
                    /* property: */ nameof(OpenIdConnectRequest.IdTokenHint),
                    /* name: */ OpenIdConnectConstants.Parameters.IdTokenHint,
                    /* value: */ "802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4"
                };

                yield return new object[] {
                    /* property: */ nameof(OpenIdConnectRequest.Nonce),
                    /* name: */ OpenIdConnectConstants.Parameters.Nonce,
                    /* value: */ "802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4"
                };

                yield return new object[] {
                    /* property: */ nameof(OpenIdConnectRequest.Password),
                    /* name: */ OpenIdConnectConstants.Parameters.Password,
                    /* value: */ "802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4"
                };

                yield return new object[] {
                    /* property: */ nameof(OpenIdConnectRequest.PostLogoutRedirectUri),
                    /* name: */ OpenIdConnectConstants.Parameters.PostLogoutRedirectUri,
                    /* value: */ "802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4"
                };

                yield return new object[] {
                    /* property: */ nameof(OpenIdConnectRequest.Prompt),
                    /* name: */ OpenIdConnectConstants.Parameters.Prompt,
                    /* value: */ "802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4"
                };

                yield return new object[] {
                    /* property: */ nameof(OpenIdConnectRequest.RedirectUri),
                    /* name: */ OpenIdConnectConstants.Parameters.RedirectUri,
                    /* value: */ "802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4"
                };

                yield return new object[] {
                    /* property: */ nameof(OpenIdConnectRequest.RefreshToken),
                    /* name: */ OpenIdConnectConstants.Parameters.RefreshToken,
                    /* value: */ "802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4"
                };

                yield return new object[] {
                    /* property: */ nameof(OpenIdConnectRequest.Request),
                    /* name: */ OpenIdConnectConstants.Parameters.Request,
                    /* value: */ "802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4"
                };

                yield return new object[] {
                    /* property: */ nameof(OpenIdConnectRequest.RequestId),
                    /* name: */ OpenIdConnectConstants.Parameters.RequestId,
                    /* value: */ "802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4"
                };

                yield return new object[] {
                    /* property: */ nameof(OpenIdConnectRequest.RequestUri),
                    /* name: */ OpenIdConnectConstants.Parameters.RequestUri,
                    /* value: */ "802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4"
                };

                yield return new object[] {
                    /* property: */ nameof(OpenIdConnectRequest.Resource),
                    /* name: */ OpenIdConnectConstants.Parameters.Resource,
                    /* value: */ "802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4"
                };

                yield return new object[] {
                    /* property: */ nameof(OpenIdConnectRequest.ResponseMode),
                    /* name: */ OpenIdConnectConstants.Parameters.ResponseMode,
                    /* value: */ "802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4"
                };

                yield return new object[] {
                    /* property: */ nameof(OpenIdConnectRequest.ResponseType),
                    /* name: */ OpenIdConnectConstants.Parameters.ResponseType,
                    /* value: */ "802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4"
                };

                yield return new object[] {
                    /* property: */ nameof(OpenIdConnectRequest.Scope),
                    /* name: */ OpenIdConnectConstants.Parameters.Scope,
                    /* value: */ "802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4"
                };

                yield return new object[] {
                    /* property: */ nameof(OpenIdConnectRequest.State),
                    /* name: */ OpenIdConnectConstants.Parameters.State,
                    /* value: */ "802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4"
                };

                yield return new object[] {
                    /* property: */ nameof(OpenIdConnectRequest.Token),
                    /* name: */ OpenIdConnectConstants.Parameters.Token,
                    /* value: */ "802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4"
                };

                yield return new object[] {
                    /* property: */ nameof(OpenIdConnectRequest.TokenTypeHint),
                    /* name: */ OpenIdConnectConstants.Parameters.TokenTypeHint,
                    /* value: */ "802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4"
                };

                yield return new object[] {
                    /* property: */ nameof(OpenIdConnectRequest.Username),
                    /* name: */ OpenIdConnectConstants.Parameters.Username,
                    /* value: */ "802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4"
                };
            }
        }

        [Theory]
        [MemberData(nameof(Properties))]
        public void PropertyGetter_ReturnsExpectedParameter(string property, string name, object value) {
            // Arrange
            var request = new OpenIdConnectRequest();
            request.SetParameter(name, JToken.FromObject(value));

            // Act and assert
            Assert.Equal(value, typeof(OpenIdConnectRequest).GetProperty(property).GetValue(request));
        }

        [Theory]
        [MemberData(nameof(Properties))]
        public void PropertySetter_AddsExpectedParameter(string property, string name, object value) {
            // Arrange
            var request = new OpenIdConnectRequest();

            // Act
            typeof(OpenIdConnectRequest).GetProperty(property).SetValue(request, value);

            // Assert
            Assert.Equal(JToken.FromObject(value), request.GetParameter(name));
        }
    }
}
