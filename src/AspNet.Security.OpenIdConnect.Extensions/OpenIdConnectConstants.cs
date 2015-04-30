/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

namespace AspNet.Security.OpenIdConnect.Extensions {
    internal static class OpenIdConnectConstants {
        public static class GrantTypes {
            public const string AuthorizationCode = "authorization_code";
            public const string ClientCredentials = "client_credentials";
            public const string Implicit = "implicit";
            public const string RefreshToken = "refresh_token";
            public const string Password = "password";
        }

        public static class ResponseModes {
            public const string FormPost = "form_post";
            public const string Fragment = "fragment";
            public const string Query = "query";
        }

        public static class ResponseTypes {
            public const string Code = "code";
            public const string IdToken = "id_token";
            public const string Token = "token";
        }
    }
}
