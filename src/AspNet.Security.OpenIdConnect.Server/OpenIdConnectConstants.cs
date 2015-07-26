/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

namespace AspNet.Security.OpenIdConnect.Server {
    internal static class OpenIdConnectConstants {
        public static class Parameters {
            public const string ResponseType = "response_type";
            public const string GrantType = "grant_type";
            public const string ClientId = "client_id";
            public const string ClientSecret = "client_secret";
            public const string RedirectUri = "redirect_uri";
            public const string Scope = "scope";
            public const string Nonce = "nonce";
            public const string State = "state";
            public const string Code = "code";
            public const string IdToken = "id_token";
            public const string RefreshToken = "refresh_token";
            public const string Username = "username";
            public const string Password = "password";
            public const string Error = "error";
            public const string ErrorDescription = "error_description";
            public const string ErrorUri = "error_uri";
            public const string ExpiresIn = "expires_in";
            public const string AccessToken = "access_token";
            public const string TokenType = "token_type";
            public const string ResponseMode = "response_mode";
        }

        public static class ResponseTypes {
            public const string Code = "code";
            public const string IdToken = "id_token";
            public const string Token = "token";
        }

        public static class ResponseModes {
            public const string FormPost = "form_post";
            public const string Fragment = "fragment";
            public const string Query = "query";
        }

        public static class Scopes {
            public const string OpenId = "openid";
        }

        public static class GrantTypes {
            public const string AuthorizationCode = "authorization_code";
            public const string ClientCredentials = "client_credentials";
            public const string Implicit = "implicit";
            public const string RefreshToken = "refresh_token";
            public const string Password = "password";
        }

        public static class TokenTypes {
            public const string Bearer = "bearer";
        }

        public static class Errors {
            public const string InvalidRequest = "invalid_request";
            public const string InvalidClient = "invalid_client";
            public const string InvalidGrant = "invalid_grant";
            public const string UnsupportedResponseType = "unsupported_response_type";
            public const string UnsupportedGrantType = "unsupported_grant_type";
            public const string UnauthorizedClient = "unauthorized_client";
            public const string ServerError = "server_error";
        }

        public static class Extra {
            public const string Audience = "audience";
            public const string ClientId = "client_id";
            public const string Destination = "destination";
            public const string Scope = "scope";
            public const string RedirectUri = "redirect_uri";
            public const string Resource = "resource";
        }

        public static class Metadata {
            public const string AuthorizationEndpoint = "authorization_endpoint";
            public const string EndSessionEndpoint = "end_session_endpoint";
            public const string IdTokenSigningAlgValuesSupported = "id_token_signing_alg_values_supported";
            public const string Issuer = "issuer";
            public const string JwksUri = "jwks_uri";
            public const string GrantTypesSupported = "grant_types_supported";
            public const string ResponseModesSupported = "response_modes_supported";
            public const string ResponseTypesSupported = "response_types_supported";
            public const string ScopesSupported = "scopes_supported";
            public const string SubjectTypesSupported = "subject_types_supported";
            public const string TokenEndpoint = "token_endpoint";
        }

        public static class SubjectTypes {
            public const string Public = "public";
            public const string Pairwise = "pairwise";
        }

        public static class Algorithms {
            public const string RS256 = "RS256";
        }

        public static class Environment {
            public const string Message = "#message";
            public const string Parameters = "#parameters";
            public const string Request = "OpenIdConnect.Request";
            public const string Response = "OpenIdConnect.Response";
        }
    }
}
