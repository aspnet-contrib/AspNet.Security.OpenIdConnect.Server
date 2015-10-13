using System;
using System.Net.Http;
using System.Text;
using Microsoft.IdentityModel.Protocols;

namespace Owin.Security.OpenIdConnect.Server.Tests {
    public static class OpenIdConnectMessageExtension {
        public static HttpRequestMessage ToHttpRequestMessage(this OpenIdConnectMessage message, HttpMethod overrideMethod = null) {
            if (message == null) {
                throw new ArgumentNullException(nameof(message));
            }

            HttpRequestMessage request;

            switch (message.RequestType) {
                case OpenIdConnectRequestType.AuthenticationRequest:
                    request = GenerateAuthenticationRequest(message, overrideMethod);
                    break;
                case OpenIdConnectRequestType.LogoutRequest:
                    request = GenerateLogoutRequest(message);
                    break;
                case OpenIdConnectRequestType.TokenRequest:
                    request = GenerateTokenRequest(message);
                    break;
                default:
                    throw new ArgumentOutOfRangeException();
            }

            request.Properties.Add("oidc_req", message);

            return request;
        }

        private static HttpRequestMessage GenerateAuthenticationRequest(OpenIdConnectMessage message, HttpMethod overrideMethod) {
            if (string.IsNullOrWhiteSpace(message.AuthorizationEndpoint)) {
                throw new InvalidOperationException("Authorization endpoint should be set value when the OpenIdConnectMessage.RequestType is OpenIdConnectRequestType.AuthenticationRequest");
            }

            if (overrideMethod == null || overrideMethod == HttpMethod.Get) {
                // Default to GET
                var sb = new StringBuilder();
                foreach (var parameter in message.Parameters) {
                    sb.Append($"&{parameter.Key}={parameter.Value}");
                }

                var builder = new UriBuilder {
                    Path = message.AuthorizationEndpoint,
                    Query = sb.Length > 1 ? Uri.EscapeUriString(sb.ToString(1, sb.Length - 1)) : string.Empty
                };

                return new HttpRequestMessage(HttpMethod.Get, builder.Uri);
            }
            if (overrideMethod == HttpMethod.Post) {
                return new HttpRequestMessage(overrideMethod, new Uri(message.AuthorizationEndpoint, UriKind.Relative)) {
                    Content = new FormUrlEncodedContent(message.Parameters),
                };
            }

            throw new InvalidOperationException();
        }

        private static HttpRequestMessage GenerateLogoutRequest(OpenIdConnectMessage message) {
            throw new NotImplementedException();
        }

        private static HttpRequestMessage GenerateTokenRequest(OpenIdConnectMessage message) {
            if (string.IsNullOrWhiteSpace(message.TokenEndpoint)) {
                throw new InvalidOperationException("Token endpoint should be set value when the OpenIdConnectMessage.RequestType is OpenIdConnectRequestType.TokenRequest");
            }

            return new HttpRequestMessage(HttpMethod.Post, new Uri(message.TokenEndpoint, UriKind.Relative)) {
                Content = new FormUrlEncodedContent(message.Parameters)
            };
        }
    }
}