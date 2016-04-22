/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

#pragma warning disable 1591

namespace Owin.Security.OpenIdConnect.Extensions {
    public static class OpenIdConnectConstants {
        public static class Algorithms {
            public const string EcdsaSha256 = "ES256";
            public const string EcdsaSha384 = "ES384";
            public const string EcdsaSha512 = "ES512";
            public const string HmacSha256 = "HS256";
            public const string HmacSha384 = "HS384";
            public const string HmacSha512 = "HS512";
            public const string RsaSha256 = "RS256";
            public const string RsaSha384 = "RS384";
            public const string RsaSha512 = "RS512";
            public const string RsaSsaPssSha256 = "PS256";
            public const string RsaSsaPssSha384 = "PS384";
            public const string RsaSsaPssSha512 = "PS512";
        }

        public static class Claims {
            public static class Protocol {
                public const string AtHash = "at_hash";
                public const string Audience = "aud";
                public const string AuthorizedParty = "azp";
                public const string Confidential = "confidential";
                public const string CryptographicHash = "c_hash";
                public const string Expires = "exp";
                public const string IssuedAt = "iat";
                public const string Issuer = "iss";
                public const string JwtId = "jti";
                public const string KeyId = "kid";
                public const string Nonce = "nonce";
                public const string NotBefore = "nbf";
                public const string Scope = "scope";
                public const string Subject = "sub";
                public const string TokenId = "token_id";
                public const string TokenType = "token_type";
                public const string Usage = "usage";
            }

            public static class Introspection {
                public const string Active = "active";
                public const string ClientId = "client_id";
                public const string UpdatedAt = "updated_at";
                public const string Username = "username";
            }

            public static class UserInfo {
                public const string Address = "address";
                public const string Birthdate = "birthdate";
                public const string Email = "email";
                public const string EmailVerified = "email_verified";
                public const string FamilyName = "family_name";
                public const string Gender = "gender";
                public const string GivenName = "given_name";
                public const string Locale = "locale";
                public const string Name = "name";
                public const string Nickname = "nickname";
                public const string MiddleName = "middle_name";
                public const string PhoneNumber = "phone_number";
                public const string PhoneNumberVerified = "phone_number_verified";
                public const string Picture = "picture";
                public const string PreferredUsername = "preferred_username";
                public const string Profile = "profile";
                public const string Subject = "sub";
                public const string Website = "website";
                public const string Zoneinfo = "zoneinfo";
            }

            public static class Address {
                public const string Formatted = "formatted";
                public const string Locality = "locality";
                public const string PostalCode = "postal_code";
                public const string Region = "region";
                public const string StreetAddress = "street_address";
            }
        }

        public static class Destinations {
            public const string AccessToken = "access_token";
            public const string IdentityToken = "id_token";
        }

        public static class Environment {
            public const string Request = "OpenIdConnect.Request";
            public const string Response = "OpenIdConnect.Response";
        }

        public static class Errors {
            public const string AccessDenied = "access_denied";
            public const string AccountSelectionRequired = "account_selection_required";
            public const string ConsentRequired = "consent_required";
            public const string InteractionRequired = "interaction_required";
            public const string InvalidClient = "invalid_client";
            public const string InvalidGrant = "invalid_grant";
            public const string InvalidRequest = "invalid_request";
            public const string LoginRequired = "login_required";
            public const string RequestNotSupported = "request_not_supported";
            public const string RequestUriNotSupported = "request_uri_not_supported";
            public const string ServerError = "server_error";
            public const string UnauthorizedClient = "unauthorized_client";
            public const string UnsupportedGrantType = "unsupported_grant_type";
            public const string UnsupportedResponseType = "unsupported_response_type";
        }

        public static class GrantTypes {
            public const string AuthorizationCode = "authorization_code";
            public const string ClientCredentials = "client_credentials";
            public const string Implicit = "implicit";
            public const string Password = "password";
            public const string RefreshToken = "refresh_token";
        }

        public static class Metadata {
            public const string AuthorizationEndpoint = "authorization_endpoint";
            public const string EndSessionEndpoint = "end_session_endpoint";
            public const string GrantTypesSupported = "grant_types_supported";
            public const string IdTokenSigningAlgValuesSupported = "id_token_signing_alg_values_supported";
            public const string IntrospectionEndpoint = "introspection_endpoint";
            public const string Issuer = "issuer";
            public const string JwksUri = "jwks_uri";
            public const string ResponseModesSupported = "response_modes_supported";
            public const string ResponseTypesSupported = "response_types_supported";
            public const string ScopesSupported = "scopes_supported";
            public const string SubjectTypesSupported = "subject_types_supported";
            public const string TokenEndpoint = "token_endpoint";
            public const string UserinfoEndpoint = "userinfo_endpoint";
        }

        public static class Parameters {
            public const string AccessToken = "access_token";
            public const string ClientId = "client_id";
            public const string ClientSecret = "client_secret";
            public const string Code = "code";
            public const string Error = "error";
            public const string ErrorDescription = "error_description";
            public const string ErrorUri = "error_uri";
            public const string ExpiresIn = "expires_in";
            public const string GrantType = "grant_type";
            public const string IdToken = "id_token";
            public const string Nonce = "nonce";
            public const string Password = "password";
            public const string RedirectUri = "redirect_uri";
            public const string RefreshToken = "refresh_token";
            public const string Request = "request";
            public const string RequestId = "request_id";
            public const string RequestUri = "request_uri";
            public const string ResponseMode = "response_mode";
            public const string ResponseType = "response_type";
            public const string Scope = "scope";
            public const string State = "state";
            public const string Token = "token";
            public const string TokenType = "token_type";
            public const string TokenTypeHint = "token_type_hint";
            public const string Username = "username";
        }

        public static class Properties {
            public const string Audiences = ".audiences";
            public const string Confidential = ".confidential";
            public const string Destinations = ".destinations";
            public const string Nonce = ".nonce";
            public const string Presenters = ".presenters";
            public const string RedirectUri = ".redirect_uri";
            public const string Resources = ".resources";
            public const string Scopes = ".scopes";
            public const string TicketId = ".ticket_id";
            public const string Usage = ".usage";
        }

        public static class ResponseModes {
            public const string FormPost = "form_post";
            public const string Fragment = "fragment";
            public const string Query = "query";
        }

        public static class ResponseTypes {
            public const string Code = "code";
            public const string IdToken = "id_token";
            public const string None = "none";
            public const string Token = "token";
        }

        public static class Scopes {
            public const string Address = "address";
            public const string Email = "email";
            public const string OfflineAccess = "offline_access";
            public const string OpenId = "openid";
            public const string Phone = "phone";
            public const string Profile = "profile";
        }

        public static class SubjectTypes {
            public const string Pairwise = "pairwise";
            public const string Public = "public";
        }

        public static class TokenTypes {
            public const string Bearer = "Bearer";
        }

        public static class Usages {
            public const string AccessToken = "access_token";
            public const string Code = "code";
            public const string IdToken = "id_token";
            public const string RefreshToken = "refresh_token";
        }
    }
}
