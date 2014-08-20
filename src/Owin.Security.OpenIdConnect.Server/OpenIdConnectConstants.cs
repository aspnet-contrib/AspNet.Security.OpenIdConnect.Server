/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/AspNet-OpenIdConnect-Server/Owin.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

namespace Owin.Security.OpenIdConnect.Server {
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

        public static class GrantTypes {
            public const string AuthorizationCode = "authorization_code";
            public const string ClientCredentials = "client_credentials";
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
        }

        public static class Extra {
            public const string ClientId = "client_id";
            public const string RedirectUri = "redirect_uri";
        }

        public static class Environment {
            public const string AuthorizeEndpointRequest = "oauth.AuthorizeEndpointRequest";
            public const string Error = "oauth.Error";
            public const string ErrorDescription = "oauth.ErrorDescription";
            public const string ErrorUri = "oauth.ErrorUri";
        }
    }
}
