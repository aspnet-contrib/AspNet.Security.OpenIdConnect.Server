using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Protocols;
using Microsoft.Owin.Security.Notifications;
using Microsoft.Owin.Testing;
using Xunit;

namespace Owin.Security.OpenIdConnect.Server.Tests {
    /// <summary>
    ///     This class tests a bunch of wrong combination calling Authorization Endpoint,
    ///     source of truth is http://openid.net/specs/openid-connect-core-1_0.html#AuthorizationEndpoint
    /// </summary>
    public class OpenIdConnectAuthorizationRequiredParameterTests {
        public static TheoryData<HttpMethod> AuthorizationEndpointHttpMethods => new TheoryData<HttpMethod> {HttpMethod.Get, HttpMethod.Post};

        [Theory]
        [MemberData("AuthorizationEndpointHttpMethods")]
        public async Task OAuthAuthorizationEndpoint_MissingClientid_BadRequest(HttpMethod method) {
            var server = TestServer.Create(app =>
                app.UseOpenIdConnectServer(options => options.AllowInsecureHttp = true));

            // Since no openid scope is passed, we should end up in OAuth2 authorization endpoint
            var response = await server.SendMessageAsync(new OpenIdConnectMessage {
                RequestType = OpenIdConnectRequestType.AuthenticationRequest,
                AuthorizationEndpoint = "connect/authorize"
            }, method);

            var openIdResponseMessage = await response.ReadAsOpenIdConnectMessageAsync();

            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidRequest, openIdResponseMessage.Error);
            Assert.Equal("client_id was missing", openIdResponseMessage.ErrorDescription);
        }

        [Theory]
        [MemberData("AuthorizationEndpointHttpMethods")]
        public async Task OAuthAuthorizationEndpoint_MissingOpenIdScope_BadRequest(HttpMethod method) {
            var server = TestServer.Create(app =>
                app.UseOpenIdConnectServer(options => {
                    options.AllowInsecureHttp = true;
                    options.Provider = new OpenIdConnectServerProvider
                    {
                        OnValidateClientRedirectUri = notification => Task.FromResult(notification.Validated("oob://something"))
                    };
                }));

            // Since no openid scope is passed, we should end up in OAuth2 authorization endpoint
            var response = await server.SendMessageAsync(new OpenIdConnectMessage {
                RequestType = OpenIdConnectRequestType.AuthenticationRequest,
                AuthorizationEndpoint = "connect/authorize",
                ResponseType = "id_token",
                ClientId = "client_id"
            }, method);

            var openIdResponseMessage = await response.ReadAsOpenIdConnectMessageAsync();

            Assert.Equal(HttpStatusCode.Found, response.StatusCode);
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidRequest, openIdResponseMessage.Error);
            Assert.Equal("openid scope missing", openIdResponseMessage.ErrorDescription);
        }

        [Theory]
        [MemberData("AuthorizationEndpointHttpMethods")]
        public async Task AuthorizationEndpoint_MissingRedirectUri_BadRequest(HttpMethod method) {
            var server = TestServer.Create(app =>
                app.UseOpenIdConnectServer(options => options.AllowInsecureHttp = true));

            var response = await server.SendMessageAsync(new OpenIdConnectMessage {
                RequestType = OpenIdConnectRequestType.AuthenticationRequest,
                AuthorizationEndpoint = "connect/authorize",
                ClientId = "client_id",
            Scope = "openid"
            }, method);

            var openIdResponseMessage = await response.ReadAsOpenIdConnectMessageAsync();

            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidRequest, openIdResponseMessage.Error);
            Assert.Equal("redirect_uri must be included when making an OpenID Connect request", openIdResponseMessage.ErrorDescription);
        }

        [Theory]
        [MemberData("AuthorizationEndpointHttpMethods")]
        public async Task AuthorizationEndpoint_MissingResponseType_BadRequest(HttpMethod method) {
            var server = TestServer.Create(app =>
                app.UseOpenIdConnectServer(options => {
                    options.AllowInsecureHttp = true;
                    options.Provider = new OpenIdConnectServerProvider {
                        OnValidateClientRedirectUri = notification => Task.FromResult(notification.Validated())
                    };
                }));

            var response = await server.SendMessageAsync(new OpenIdConnectMessage {
                RequestType = OpenIdConnectRequestType.AuthenticationRequest,
                AuthorizationEndpoint = "connect/authorize",
                Scope = "openid",
                RedirectUri = "oob://something",
                ClientId = "client_id"
            }, method);

            var openIdResponseMessage = await response.ReadAsOpenIdConnectMessageAsync();

            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidRequest, openIdResponseMessage.Error);
            Assert.Equal("response_type parameter missing", openIdResponseMessage.ErrorDescription);
        }

        [Theory]
        [MemberData("AuthorizationEndpointHttpMethods")]
        public async Task AuthorizationEndpoint_InvalidResponseType_BadRequest(HttpMethod method) {
            var server = TestServer.Create(app =>
                app.UseOpenIdConnectServer(options => {
                    options.AllowInsecureHttp = true;
                    options.Provider = new OpenIdConnectServerProvider {
                        OnValidateClientRedirectUri = notification => Task.FromResult(notification.Validated())
                    };
                }));

            var response = await server.SendMessageAsync(new OpenIdConnectMessage {
                RequestType = OpenIdConnectRequestType.AuthenticationRequest,
                AuthorizationEndpoint = "connect/authorize",
                Scope = "openid",
                RedirectUri = "oob://something",
                ClientId = "client_id",
                ResponseType = "somevalue" // should be code!
            }, method);

            var openIdResponseMessage = await response.ReadAsOpenIdConnectMessageAsync();

            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            Assert.Equal(OpenIdConnectConstants.Errors.UnsupportedResponseType, openIdResponseMessage.Error);
            Assert.Equal("response_type unsupported", openIdResponseMessage.ErrorDescription);
        }

        [Theory]
        [MemberData("AuthorizationEndpointHttpMethods")]
        public async Task AuthorizationEndpoint_MissingNonce_BadRequest(HttpMethod method) {
            var server = TestServer.Create(app =>
                app.UseOpenIdConnectServer(options => {
                    options.AllowInsecureHttp = true;
                    options.Provider = new OpenIdConnectServerProvider {
                        OnValidateClientRedirectUri = notification => Task.FromResult(notification.Validated())
                    };
                }));

            var response = await server.SendMessageAsync(new OpenIdConnectMessage {
                RequestType = OpenIdConnectRequestType.AuthenticationRequest,
                AuthorizationEndpoint = "connect/authorize",
                Scope = "openid",
                RedirectUri = "oob://something",
                ResponseType = "token",
                ClientId = "client_id"
            }, method);

            var openIdResponseMessage = await response.ReadAsOpenIdConnectMessageAsync();

            Assert.Equal(HttpStatusCode.Found, response.StatusCode);
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidRequest, openIdResponseMessage.Error);
            Assert.Equal("nonce parameter missing", openIdResponseMessage.ErrorDescription);
        }
    }

    public class OpenIdConnectPositiveAuthorizationTests {
        private const string UnsupportedCombinationError = "response_type/response_mode combination unsupported";
        private const string NonceParameterMissingError = "nonce parameter missing";

        private TestServer CreateTrustEveryoneEmptyIdentityServer  => 
            TestServer.Create(app =>
                    app.UseOpenIdConnectServer(options => {
                        options.AllowInsecureHttp = true;
                        options.UseTestCertificate();
                        options.Provider = new TrustEveryoneEmptyIdentityOpenIdConnectServerProvider();
                    }));

        private TestServer CreateTrustEveryoneServer => 
            TestServer.Create(app =>
                    app.UseOpenIdConnectServer(options => {
                        options.AllowInsecureHttp = true;
                        options.UseTestCertificate();
                        options.Provider = new TrustEveryoneOpenIdConnectServerProvider();
                    }));

        public static TheoryData<HttpMethod> AuthorizationEndpointHttpMethods => new TheoryData<HttpMethod> {HttpMethod.Get, HttpMethod.Post};

        [Theory]
        [MemberData("AuthorizationEndpointHttpMethods")]
        public async Task AuthorizationCodeFlow_FormPost_Ok(HttpMethod method) {
            var server = CreateTrustEveryoneEmptyIdentityServer;

            var response = await server.SendMessageAsync(new OpenIdConnectMessage {
                AuthorizationEndpoint = "connect/authorize",
                ClientId = "client_id",
                RedirectUri = "oob://something",
                RequestType = OpenIdConnectRequestType.AuthenticationRequest,
                ResponseMode = OpenIdConnectConstants.ResponseModes.FormPost,
                ResponseType = OpenIdConnectConstants.ResponseTypes.Code,
                Scope = "openid"
            }, method);

            var openIdResponseMessage = await response.ReadAsOpenIdConnectMessageAsync();

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.True(!string.IsNullOrEmpty(openIdResponseMessage.Code));
        }

        [Theory]
        [MemberData("AuthorizationEndpointHttpMethods")]
        public async Task AuthorizationCodeFlow_Query_Found(HttpMethod method) {
            var server = CreateTrustEveryoneEmptyIdentityServer;

            var response = await server.SendMessageAsync(new OpenIdConnectMessage {
                AuthorizationEndpoint = "connect/authorize",
                ClientId = "client_id",
                RedirectUri = "oob://something",
                RequestType = OpenIdConnectRequestType.AuthenticationRequest,
                ResponseMode = OpenIdConnectConstants.ResponseModes.Query,
                ResponseType = OpenIdConnectConstants.ResponseTypes.Code,
                Scope = "openid"
            }, method);

            var openIdResponseMessage = await response.ReadAsOpenIdConnectMessageAsync();

            Assert.Equal(HttpStatusCode.Found, response.StatusCode);
            Assert.Equal("something", response.Headers.Location.Host);
            Assert.True(!string.IsNullOrEmpty(openIdResponseMessage.Code));
        }

        [Theory]
        [MemberData("AuthorizationEndpointHttpMethods")]
        public async Task AuthorizationCodeFlowInvalidCombination_Fragment_FoundWithError(HttpMethod method) {
            var server = CreateTrustEveryoneEmptyIdentityServer;

            var response = await server.SendMessageAsync(new OpenIdConnectMessage {
                AuthorizationEndpoint = "connect/authorize",
                ClientId = "client_id",
                RedirectUri = "oob://something",
                RequestType = OpenIdConnectRequestType.AuthenticationRequest,
                ResponseMode = OpenIdConnectConstants.ResponseModes.Fragment,
                ResponseType = OpenIdConnectConstants.ResponseTypes.Code,
                Scope = "openid"
            }, method);

            var openIdResponseMessage = await response.ReadAsOpenIdConnectMessageAsync();

            Assert.Equal(HttpStatusCode.Found, response.StatusCode);
            Assert.Equal("something", response.Headers.Location.Host);
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidRequest, openIdResponseMessage.Error);
            Assert.Equal(UnsupportedCombinationError, openIdResponseMessage.ErrorDescription);
        }

        [Theory]
        [ActiveIssue("https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server/issues/112")]
        [MemberData("AuthorizationEndpointHttpMethods")]
        public async Task ImplicitFlowIdTokenInvalidIdentity_Fragment_BadRequest(HttpMethod method) {
            var server = CreateTrustEveryoneEmptyIdentityServer;

            var response = await server.SendMessageAsync(new OpenIdConnectMessage {
                AuthorizationEndpoint = "connect/authorize",
                ClientId = "client_id",
                RedirectUri = "oob://something",
                RequestType = OpenIdConnectRequestType.AuthenticationRequest,
                ResponseMode = OpenIdConnectConstants.ResponseModes.Fragment,
                ResponseType = OpenIdConnectConstants.ResponseTypes.IdToken,
                Scope = "openid",
                Nonce = "nonce with sufficient entropy"
            }, method);

            var openIdResponseMessage = await response.ReadAsOpenIdConnectMessageAsync();

            Assert.Equal(HttpStatusCode.Found, response.StatusCode);
            Assert.True(!string.IsNullOrEmpty(openIdResponseMessage.Error));
        }

        [Theory]
        [MemberData("AuthorizationEndpointHttpMethods")]
        public async Task ImplicitFlowIdTokenMissingNonce_FormPost_OkWithError(HttpMethod method) {
            var server = CreateTrustEveryoneEmptyIdentityServer;

            var response = await server.SendMessageAsync(new OpenIdConnectMessage {
                AuthorizationEndpoint = "connect/authorize",
                ClientId = "client_id",
                RedirectUri = "oob://something",
                RequestType = OpenIdConnectRequestType.AuthenticationRequest,
                ResponseMode = OpenIdConnectConstants.ResponseModes.FormPost,
                ResponseType = OpenIdConnectConstants.ResponseTypes.IdToken,
                Scope = "openid"
            }, method);

            var openIdResponseMessage = await response.ReadAsOpenIdConnectMessageAsync();

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidRequest, openIdResponseMessage.Error);
            Assert.Equal(NonceParameterMissingError, openIdResponseMessage.ErrorDescription);
        }

        [Theory]
        [MemberData("AuthorizationEndpointHttpMethods")]
        public async Task ImplicitFlowIdToken_FormPost_Ok(HttpMethod method) {
            var server = CreateTrustEveryoneServer;

            var response = await server.SendMessageAsync(new OpenIdConnectMessage {
                AuthorizationEndpoint = "connect/authorize",
                ClientId = "client_id",
                RedirectUri = "oob://something",
                RequestType = OpenIdConnectRequestType.AuthenticationRequest,
                ResponseMode = OpenIdConnectConstants.ResponseModes.FormPost,
                ResponseType = OpenIdConnectConstants.ResponseTypes.IdToken,
                Scope = "openid",
                Nonce = "nonce with sufficient entropy"
            }, method);

            var openIdResponseMessage = await response.ReadAsOpenIdConnectMessageAsync();

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.True(!string.IsNullOrEmpty(openIdResponseMessage.IdToken));
        }

        [Theory]
        [MemberData("AuthorizationEndpointHttpMethods")]
        public async Task ImplicitFlowIdTokenInvalidCombination_Query_FoundWithError(HttpMethod method) {
            var server = CreateTrustEveryoneServer;

            var response = await server.SendMessageAsync(new OpenIdConnectMessage {
                AuthorizationEndpoint = "connect/authorize",
                ClientId = "client_id",
                RedirectUri = "oob://something",
                RequestType = OpenIdConnectRequestType.AuthenticationRequest,
                ResponseMode = OpenIdConnectConstants.ResponseModes.Query,
                ResponseType = OpenIdConnectConstants.ResponseTypes.IdToken,
                Scope = "openid",
                Nonce = "nonce with sufficient entropy"
            }, method);

            var openIdResponseMessage = await response.ReadAsOpenIdConnectMessageAsync();

            Assert.Equal(HttpStatusCode.Found, response.StatusCode);
            Assert.Equal("something", response.Headers.Location.Host);
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidRequest, openIdResponseMessage.Error);
            Assert.Equal(UnsupportedCombinationError, openIdResponseMessage.ErrorDescription);
        }

        [Theory]
        [MemberData("AuthorizationEndpointHttpMethods")]
        public async Task ImplicitFlowIdToken_Fragment_Found(HttpMethod method) {
            var server = CreateTrustEveryoneServer;

            var response = await server.SendMessageAsync(new OpenIdConnectMessage {
                AuthorizationEndpoint = "connect/authorize",
                ClientId = "client_id",
                RedirectUri = "oob://something",
                RequestType = OpenIdConnectRequestType.AuthenticationRequest,
                ResponseMode = OpenIdConnectConstants.ResponseModes.Fragment,
                ResponseType = OpenIdConnectConstants.ResponseTypes.IdToken,
                Scope = "openid",
                Nonce = "nonce with sufficient entropy"
            }, method);

            var openIdResponseMessage = await response.ReadAsOpenIdConnectMessageAsync();

            Assert.Equal(HttpStatusCode.Found, response.StatusCode);
            Assert.Equal("something", response.Headers.Location.Host);
            Assert.True(!string.IsNullOrEmpty(openIdResponseMessage.IdToken));
        }

        [Theory]
        [MemberData("AuthorizationEndpointHttpMethods")]
        public async Task ImplicitFlowIdTokenAndToken_FormPost_Ok(HttpMethod method) {
            var server = CreateTrustEveryoneServer;

            var response = await server.SendMessageAsync(new OpenIdConnectMessage {
                AuthorizationEndpoint = "connect/authorize",
                ClientId = "client_id",
                RedirectUri = "oob://something",
                RequestType = OpenIdConnectRequestType.AuthenticationRequest,
                ResponseMode = OpenIdConnectConstants.ResponseModes.FormPost,
                ResponseType = OpenIdConnectConstants.ResponseTypes.IdToken + " " + OpenIdConnectConstants.ResponseTypes.Token,
                Scope = "openid",
                Nonce = "nonce with sufficient entropy"
            }, method);

            var openIdResponseMessage = await response.ReadAsOpenIdConnectMessageAsync();

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.True(!string.IsNullOrEmpty(openIdResponseMessage.IdToken));
            Assert.True(!string.IsNullOrEmpty(openIdResponseMessage.AccessToken));
        }

        [Theory]
        [MemberData("AuthorizationEndpointHttpMethods")]
        public async Task ImplicitFlowIdTokenAccessTokenInvalidCombination_Query_FoundWithError(HttpMethod method) {
            var server = CreateTrustEveryoneServer;

            var response = await server.SendMessageAsync(new OpenIdConnectMessage {
                AuthorizationEndpoint = "connect/authorize",
                ClientId = "client_id",
                RedirectUri = "oob://something",
                RequestType = OpenIdConnectRequestType.AuthenticationRequest,
                ResponseMode = OpenIdConnectConstants.ResponseModes.Query,
                ResponseType = OpenIdConnectConstants.ResponseTypes.IdToken + " " + OpenIdConnectConstants.ResponseTypes.Token,
                Scope = "openid",
                Nonce = "nonce with sufficient entropy"
            }, method);

            var openIdResponseMessage = await response.ReadAsOpenIdConnectMessageAsync();

            Assert.Equal(HttpStatusCode.Found, response.StatusCode);
            Assert.Equal("something", response.Headers.Location.Host);
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidRequest, openIdResponseMessage.Error);
            Assert.Equal(UnsupportedCombinationError, openIdResponseMessage.ErrorDescription);
        }

        [Theory]
        [MemberData("AuthorizationEndpointHttpMethods")]
        public async Task ImplicitFlowIdTokenAccessToken_Fragment_Found(HttpMethod method) {
            var server = CreateTrustEveryoneServer;

            var response = await server.SendMessageAsync(new OpenIdConnectMessage {
                AuthorizationEndpoint = "connect/authorize",
                ClientId = "client_id",
                RedirectUri = "oob://something",
                RequestType = OpenIdConnectRequestType.AuthenticationRequest,
                ResponseMode = OpenIdConnectConstants.ResponseModes.Fragment,
                ResponseType = OpenIdConnectConstants.ResponseTypes.IdToken + " " + OpenIdConnectConstants.ResponseTypes.Token,
                Scope = "openid",
                Nonce = "nonce with sufficient entropy"
            }, method);

            var openIdResponseMessage = await response.ReadAsOpenIdConnectMessageAsync();

            Assert.Equal(HttpStatusCode.Found, response.StatusCode);
            Assert.Equal("something", response.Headers.Location.Host);
            Assert.True(!string.IsNullOrEmpty(openIdResponseMessage.IdToken));
            Assert.True(!string.IsNullOrEmpty(openIdResponseMessage.AccessToken));
        }

        [Theory]
        [MemberData("AuthorizationEndpointHttpMethods")]
        public async Task HybridFlowCodeIdTokenMissingNonce_FormPost_OkWithError(HttpMethod method) {
            var server = CreateTrustEveryoneServer;

            var response = await server.SendMessageAsync(new OpenIdConnectMessage {
                AuthorizationEndpoint = "connect/authorize",
                ClientId = "client_id",
                RedirectUri = "oob://something",
                RequestType = OpenIdConnectRequestType.AuthenticationRequest,
                ResponseMode = OpenIdConnectConstants.ResponseModes.FormPost,
                ResponseType = "code id_token",
                Scope = "openid"
            }, method);

            var openIdResponseMessage = await response.ReadAsOpenIdConnectMessageAsync();

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidRequest, openIdResponseMessage.Error);
            Assert.Equal(NonceParameterMissingError, openIdResponseMessage.ErrorDescription);
        }

        [Theory]
        [MemberData("AuthorizationEndpointHttpMethods")]
        public async Task HybridFlowCodeIdToken_FormPost_Ok(HttpMethod method) {
            var server = CreateTrustEveryoneServer;

            var response = await server.SendMessageAsync(new OpenIdConnectMessage {
                AuthorizationEndpoint = "connect/authorize",
                ClientId = "client_id",
                RedirectUri = "oob://something",
                RequestType = OpenIdConnectRequestType.AuthenticationRequest,
                ResponseMode = OpenIdConnectConstants.ResponseModes.FormPost,
                ResponseType = "code id_token",
                Scope = "openid",
                Nonce = "nonce with sufficient entropy"
            }, method);

            var openIdResponseMessage = await response.ReadAsOpenIdConnectMessageAsync();

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.True(!string.IsNullOrEmpty(openIdResponseMessage.Code));
            Assert.True(!string.IsNullOrEmpty(openIdResponseMessage.IdToken));
        }

        [Theory]
        [MemberData("AuthorizationEndpointHttpMethods")]
        public async Task HybridFlowCodeIdTokenInvalidCombination_Query_FoundWithError(HttpMethod method) {
            var server = CreateTrustEveryoneServer;

            var response = await server.SendMessageAsync(new OpenIdConnectMessage {
                AuthorizationEndpoint = "connect/authorize",
                ClientId = "client_id",
                RedirectUri = "oob://something",
                RequestType = OpenIdConnectRequestType.AuthenticationRequest,
                ResponseMode = OpenIdConnectConstants.ResponseModes.Query,
                ResponseType = "code id_token",
                Scope = "openid",
                Nonce = "nonce with sufficient entropy"
            }, method);

            var openIdResponseMessage = await response.ReadAsOpenIdConnectMessageAsync();

            Assert.Equal(HttpStatusCode.Found, response.StatusCode);
            Assert.Equal("something", response.Headers.Location.Host);
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidRequest, openIdResponseMessage.Error);
            Assert.Equal(UnsupportedCombinationError, openIdResponseMessage.ErrorDescription);
        }

        [Theory]
        [MemberData("AuthorizationEndpointHttpMethods")]
        public async Task HybridFlowCodeIdToken_Fragment_Found(HttpMethod method) {
            var server = CreateTrustEveryoneServer;

            var response = await server.SendMessageAsync(new OpenIdConnectMessage {
                AuthorizationEndpoint = "connect/authorize",
                ClientId = "client_id",
                RedirectUri = "oob://something",
                RequestType = OpenIdConnectRequestType.AuthenticationRequest,
                ResponseMode = OpenIdConnectConstants.ResponseModes.Fragment,
                ResponseType = "code id_token",
                Scope = "openid",
                Nonce = "nonce with sufficient entropy"
            }, method);

            var openIdResponseMessage = await response.ReadAsOpenIdConnectMessageAsync();

            Assert.Equal(HttpStatusCode.Found, response.StatusCode);
            Assert.Equal("something", response.Headers.Location.Host);
            Assert.True(!string.IsNullOrEmpty(openIdResponseMessage.Code));
            Assert.True(!string.IsNullOrEmpty(openIdResponseMessage.IdToken));
        }

        [Theory]
        [MemberData("AuthorizationEndpointHttpMethods")]
        public async Task HybridFlowCodeTokenMissingNonce_FormPost_OkWithError(HttpMethod method) {
            var server = CreateTrustEveryoneServer;

            var response = await server.SendMessageAsync(new OpenIdConnectMessage {
                AuthorizationEndpoint = "connect/authorize",
                ClientId = "client_id",
                RedirectUri = "oob://something",
                RequestType = OpenIdConnectRequestType.AuthenticationRequest,
                ResponseMode = OpenIdConnectConstants.ResponseModes.FormPost,
                ResponseType = "code token",
                Scope = "openid"
            }, method);

            var openIdResponseMessage = await response.ReadAsOpenIdConnectMessageAsync();

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidRequest, openIdResponseMessage.Error);
            Assert.Equal(NonceParameterMissingError, openIdResponseMessage.ErrorDescription);
        }

        [Theory]
        [MemberData("AuthorizationEndpointHttpMethods")]
        public async Task HybridFlowCodeToken_FormPost_Ok(HttpMethod method) {
            var server = CreateTrustEveryoneServer;

            var response = await server.SendMessageAsync(new OpenIdConnectMessage {
                AuthorizationEndpoint = "connect/authorize",
                ClientId = "client_id",
                RedirectUri = "oob://something",
                RequestType = OpenIdConnectRequestType.AuthenticationRequest,
                ResponseMode = OpenIdConnectConstants.ResponseModes.FormPost,
                ResponseType = "code token",
                Scope = "openid",
                Nonce = "nonce with sufficient entropy"
            }, method);

            var openIdResponseMessage = await response.ReadAsOpenIdConnectMessageAsync();

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.True(!string.IsNullOrEmpty(openIdResponseMessage.Code));
        }

        [Theory]
        [MemberData("AuthorizationEndpointHttpMethods")]
        public async Task HybridFlowCodeTokenInvalidCombination_Query_FoundWithError(HttpMethod method) {
            var server = CreateTrustEveryoneServer;

            var response = await server.SendMessageAsync(new OpenIdConnectMessage {
                AuthorizationEndpoint = "connect/authorize",
                ClientId = "client_id",
                RedirectUri = "oob://something",
                RequestType = OpenIdConnectRequestType.AuthenticationRequest,
                ResponseMode = OpenIdConnectConstants.ResponseModes.Query,
                ResponseType = "code token",
                Scope = "openid",
                Nonce = "nonce with sufficient entropy"
            }, method);

            var openIdResponseMessage = await response.ReadAsOpenIdConnectMessageAsync();

            Assert.Equal(HttpStatusCode.Found, response.StatusCode);
            Assert.Equal("something", response.Headers.Location.Host);
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidRequest, openIdResponseMessage.Error);
            Assert.Equal(UnsupportedCombinationError, openIdResponseMessage.ErrorDescription);
        }

        [Theory]
        [MemberData("AuthorizationEndpointHttpMethods")]
        public async Task HybridFlowCodeToken_Fragment_Found(HttpMethod method) {
            var server = CreateTrustEveryoneServer;

            var response = await server.SendMessageAsync(new OpenIdConnectMessage {
                AuthorizationEndpoint = "connect/authorize",
                ClientId = "client_id",
                RedirectUri = "oob://something",
                RequestType = OpenIdConnectRequestType.AuthenticationRequest,
                ResponseMode = OpenIdConnectConstants.ResponseModes.Fragment,
                ResponseType = "code id_token",
                Scope = "openid",
                Nonce = "nonce with sufficient entropy"
            }, method);

            var openIdResponseMessage = await response.ReadAsOpenIdConnectMessageAsync();

            Assert.Equal(HttpStatusCode.Found, response.StatusCode);
            Assert.Equal("something", response.Headers.Location.Host);
            Assert.True(!string.IsNullOrEmpty(openIdResponseMessage.Code));
        }

        [Theory]
        [MemberData("AuthorizationEndpointHttpMethods")]
        public async Task HybridFlowCodeIdTokenAccessTokenMissingNonce_FormPost_FoundWithError(HttpMethod method) {
            var server = CreateTrustEveryoneServer;

            var response = await server.SendMessageAsync(new OpenIdConnectMessage {
                AuthorizationEndpoint = "connect/authorize",
                ClientId = "client_id",
                RedirectUri = "oob://something",
                RequestType = OpenIdConnectRequestType.AuthenticationRequest,
                ResponseMode = OpenIdConnectConstants.ResponseModes.FormPost,
                ResponseType = "code id_token token",
                Scope = "openid"
            }, method);

            var openIdResponseMessage = await response.ReadAsOpenIdConnectMessageAsync();

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidRequest, openIdResponseMessage.Error);
            Assert.Equal(NonceParameterMissingError, openIdResponseMessage.ErrorDescription);
        }

        [Theory]
        [MemberData("AuthorizationEndpointHttpMethods")]
        public async Task HybridFlowCodeIdTokenAccessToken_FormPost_Ok(HttpMethod method) {
            var server = CreateTrustEveryoneServer;

            var response = await server.SendMessageAsync(new OpenIdConnectMessage {
                AuthorizationEndpoint = "connect/authorize",
                ClientId = "client_id",
                RedirectUri = "oob://something",
                RequestType = OpenIdConnectRequestType.AuthenticationRequest,
                ResponseMode = OpenIdConnectConstants.ResponseModes.FormPost,
                ResponseType = "code id_token token",
                Scope = "openid",
                Nonce = "nonce with sufficient entropy"
            }, method);

            var openIdResponseMessage = await response.ReadAsOpenIdConnectMessageAsync();

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.True(!string.IsNullOrEmpty(openIdResponseMessage.Code));
            Assert.True(!string.IsNullOrEmpty(openIdResponseMessage.IdToken));
            Assert.True(string.IsNullOrEmpty(openIdResponseMessage.Token));
        }

        [Theory]
        [MemberData("AuthorizationEndpointHttpMethods")]
        public async Task HybridFlowCodeIdTokenAccessTokenInvalidCombination_Query_FoundWithError(HttpMethod method) {
            var server = CreateTrustEveryoneServer;

            var response = await server.SendMessageAsync(new OpenIdConnectMessage {
                AuthorizationEndpoint = "connect/authorize",
                ClientId = "client_id",
                RedirectUri = "oob://something",
                RequestType = OpenIdConnectRequestType.AuthenticationRequest,
                ResponseMode = OpenIdConnectConstants.ResponseModes.Query,
                ResponseType = "code id_token token",
                Scope = "openid",
                Nonce = "nonce with sufficient entropy"
            }, method);

            var openIdResponseMessage = await response.ReadAsOpenIdConnectMessageAsync();

            Assert.Equal(HttpStatusCode.Found, response.StatusCode);
            Assert.Equal("something", response.Headers.Location.Host);
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidRequest, openIdResponseMessage.Error);
            Assert.Equal(UnsupportedCombinationError, openIdResponseMessage.ErrorDescription);
        }

        [Theory]
        [MemberData("AuthorizationEndpointHttpMethods")]
        public async Task HybridFlowCodeIdTokenAccessToken_Fragment_Found(HttpMethod method) {
            var server = CreateTrustEveryoneServer;

            var response = await server.SendMessageAsync(new OpenIdConnectMessage {
                AuthorizationEndpoint = "connect/authorize",
                ClientId = "client_id",
                RedirectUri = "oob://something",
                RequestType = OpenIdConnectRequestType.AuthenticationRequest,
                ResponseMode = OpenIdConnectConstants.ResponseModes.Fragment,
                ResponseType = "code id_token token",
                Scope = "openid",
                Nonce = "nonce with sufficient entropy"
            }, method);

            var openIdResponseMessage = await response.ReadAsOpenIdConnectMessageAsync();

            Assert.Equal(HttpStatusCode.Found, response.StatusCode);
            Assert.Equal("something", response.Headers.Location.Host);
            Assert.True(!string.IsNullOrEmpty(openIdResponseMessage.Code));
            Assert.True(!string.IsNullOrEmpty(openIdResponseMessage.IdToken));
            Assert.True(string.IsNullOrEmpty(openIdResponseMessage.Token));
        }

        private class TrustEveryoneEmptyIdentityOpenIdConnectServerProvider : OpenIdConnectServerProvider {
            public TrustEveryoneEmptyIdentityOpenIdConnectServerProvider() {
                OnValidateClientRedirectUri = notification => Task.FromResult(notification.Validated());
                OnAuthorizationEndpoint = notification => {
                    notification.OwinContext.Authentication.SignIn(new ClaimsIdentity(notification.Options.AuthenticationType));
                    notification.State = NotificationResultState.HandledResponse;
                    return Task.FromResult<object>(null);
                };
            }
        }

        private class TrustEveryoneOpenIdConnectServerProvider : OpenIdConnectServerProvider {
            public TrustEveryoneOpenIdConnectServerProvider() {
                OnValidateClientRedirectUri = notification => Task.FromResult(notification.Validated());
                OnAuthorizationEndpoint = notification => {
                    notification.OwinContext.Authentication.SignIn(
                        new ClaimsIdentity(new[] {new Claim(ClaimTypes.NameIdentifier, "it's me", ClaimValueTypes.String)},
                            notification.Options.AuthenticationType));
                    notification.State = NotificationResultState.HandledResponse;
                    return Task.FromResult<object>(null);
                };
            }
        }
    }
}