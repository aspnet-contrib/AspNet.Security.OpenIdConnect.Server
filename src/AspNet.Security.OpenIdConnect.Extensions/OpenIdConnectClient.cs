using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Threading.Tasks;
using AngleSharp.Parser.Html;
using JetBrains.Annotations;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Primitives;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace AspNet.Security.OpenIdConnect.Extensions {
    /// <summary>
    /// Exposes methods that allow sending OpenID Connect
    /// requests and extracting the corresponding responses.
    /// </summary>
    public class OpenIdConnectClient {
        /// <summary>
        /// Initializes a new instance of the OpenID Connect client.
        /// </summary>
        public OpenIdConnectClient() {
            HttpClient = new HttpClient();
        }

        /// <summary>
        /// Initializes a new instance of the OpenID Connect client.
        /// </summary>
        /// <param name="client">The HTTP client used to communicate with the OpenID Connect server.</param>
        public OpenIdConnectClient([NotNull] HttpClient client) {
            if (client == null) {
                throw new ArgumentNullException(nameof(client));
            }

            HttpClient = client;
        }

        /// <summary>
        /// Gets the underlying HTTP client used to
        /// communicate with the OpenID Connect server.
        /// </summary>
        public HttpClient HttpClient { get; }

        /// <summary>
        /// Sends an empty OpenID Connect request to the given endpoint using GET
        /// and converts the returned response to an OpenID Connect response.
        /// </summary>
        /// <param name="address">The endpoint to which the request is sent.</param>
        /// <returns>The OpenID Connect response returned by the server.</returns>
        public Task<OpenIdConnectResponse> GetAsync([NotNull] string address) {
            return GetAsync(address, new OpenIdConnectRequest());
        }

        /// <summary>
        /// Sends an empty OpenID Connect request to the given endpoint using GET
        /// and converts the returned response to an OpenID Connect response.
        /// </summary>
        /// <param name="address">The endpoint to which the request is sent.</param>
        /// <returns>The OpenID Connect response returned by the server.</returns>
        public Task<OpenIdConnectResponse> GetAsync([NotNull] Uri address) {
            return GetAsync(address, new OpenIdConnectRequest());
        }

        /// <summary>
        /// Sends a generic OpenID Connect request to the given endpoint using GET
        /// and converts the returned response to an OpenID Connect response.
        /// </summary>
        /// <param name="address">The endpoint to which the request is sent.</param>
        /// <param name="request">The OpenID Connect request to send.</param>
        /// <returns>The OpenID Connect response returned by the server.</returns>
        public Task<OpenIdConnectResponse> GetAsync(
            [NotNull] string address, [NotNull] OpenIdConnectRequest request) {
            if (address == null) {
                throw new ArgumentNullException(nameof(address));
            }

            if (request == null) {
                throw new ArgumentNullException(nameof(request));
            }

            return GetAsync(new Uri(address, UriKind.RelativeOrAbsolute), request);
        }

        /// <summary>
        /// Sends a generic OpenID Connect request to the given endpoint using GET
        /// and converts the returned response to an OpenID Connect response.
        /// </summary>
        /// <param name="address">The endpoint to which the request is sent.</param>
        /// <param name="request">The OpenID Connect request to send.</param>
        /// <returns>The OpenID Connect response returned by the server.</returns>
        public Task<OpenIdConnectResponse> GetAsync(
            [NotNull] Uri address, [NotNull] OpenIdConnectRequest request) {
            return SendAsync(HttpMethod.Get, address, request);
        }

        /// <summary>
        /// Sends a generic OpenID Connect request to the given endpoint using POST
        /// and converts the returned response to an OpenID Connect response.
        /// </summary>
        /// <param name="address">The endpoint to which the request is sent.</param>
        /// <param name="request">The OpenID Connect request to send.</param>
        /// <returns>The OpenID Connect response returned by the server.</returns>
        public Task<OpenIdConnectResponse> PostAsync(
            [NotNull] string address, [NotNull] OpenIdConnectRequest request) {
            if (address == null) {
                throw new ArgumentNullException(nameof(address));
            }

            if (request == null) {
                throw new ArgumentNullException(nameof(request));
            }

            return PostAsync(new Uri(address, UriKind.RelativeOrAbsolute), request);
        }

        /// <summary>
        /// Sends a generic OpenID Connect request to the given endpoint using POST
        /// and converts the returned response to an OpenID Connect response.
        /// </summary>
        /// <param name="address">The endpoint to which the request is sent.</param>
        /// <param name="request">The OpenID Connect request to send.</param>
        /// <returns>The OpenID Connect response returned by the server.</returns>
        public Task<OpenIdConnectResponse> PostAsync(
            [NotNull] Uri address, [NotNull] OpenIdConnectRequest request) {
            return SendAsync(HttpMethod.Post, address, request);
        }

        /// <summary>
        /// Sends a generic OpenID Connect request to the given endpoint and
        /// converts the returned response to an OpenID Connect response.
        /// </summary>
        /// <param name="method">The HTTP method used to send the OpenID Connect request.</param>
        /// <param name="address">The endpoint to which the request is sent.</param>
        /// <param name="request">The OpenID Connect request to send.</param>
        /// <returns>The OpenID Connect response returned by the server.</returns>
        public Task<OpenIdConnectResponse> SendAsync(
            [NotNull] string method, [NotNull] string address,
            [NotNull] OpenIdConnectRequest request) {
            if (method == null) {
                throw new ArgumentNullException(nameof(method));
            }

            if (address == null) {
                throw new ArgumentNullException(nameof(address));
            }

            if (request == null) {
                throw new ArgumentNullException(nameof(request));
            }

            return SendAsync(new HttpMethod(method), address, request);
        }

        /// <summary>
        /// Sends a generic OpenID Connect request to the given endpoint and
        /// converts the returned response to an OpenID Connect response.
        /// </summary>
        /// <param name="method">The HTTP method used to send the OpenID Connect request.</param>
        /// <param name="address">The endpoint to which the request is sent.</param>
        /// <param name="request">The OpenID Connect request to send.</param>
        /// <returns>The OpenID Connect response returned by the server.</returns>
        public Task<OpenIdConnectResponse> SendAsync(
            [NotNull] HttpMethod method, [NotNull] string address,
            [NotNull] OpenIdConnectRequest request) {
            if (method == null) {
                throw new ArgumentNullException(nameof(method));
            }

            if (address == null) {
                throw new ArgumentNullException(nameof(address));
            }

            if (request == null) {
                throw new ArgumentNullException(nameof(request));
            }

            return SendAsync(method, new Uri(address, UriKind.RelativeOrAbsolute), request);
        }

        /// <summary>
        /// Sends a generic OpenID Connect request to the given endpoint and
        /// converts the returned response to an OpenID Connect response.
        /// </summary>
        /// <param name="method">The HTTP method used to send the OpenID Connect request.</param>
        /// <param name="address">The endpoint to which the request is sent.</param>
        /// <param name="request">The OpenID Connect request to send.</param>
        /// <returns>The OpenID Connect response returned by the server.</returns>
        public virtual async Task<OpenIdConnectResponse> SendAsync(
            [NotNull] HttpMethod method, [NotNull] Uri address,
            [NotNull] OpenIdConnectRequest request) {
            if (method == null) {
                throw new ArgumentNullException(nameof(method));
            }

            if (address == null) {
                throw new ArgumentNullException(nameof(address));
            }

            if (request == null) {
                throw new ArgumentNullException(nameof(request));
            }

            var parameters = new Dictionary<string, string>();

            foreach (var parameter in request) {
                var value = parameter.Value as JValue;
                if (value == null) {
                    continue;
                }

                parameters.Add(parameter.Key, (string) parameter.Value);
            }

            if (method == HttpMethod.Get) {
                var url = QueryHelpers.AddQueryString(address.ToString(), parameters);

                address = new Uri(url, address.IsAbsoluteUri ? UriKind.Absolute : UriKind.RelativeOrAbsolute);
            }

            var message = new HttpRequestMessage(method, address);

            if (method != HttpMethod.Get) {
                message.Content = new FormUrlEncodedContent(parameters);
            }

            var response = await HttpClient.SendAsync(message, HttpCompletionOption.ResponseHeadersRead);

            if (response.Headers.Location != null) {
                var payload = response.Headers.Location.Fragment;
                if (string.IsNullOrEmpty(payload)) {
                    payload = response.Headers.Location.Query;
                }

                if (string.IsNullOrEmpty(payload)) {
                    return new OpenIdConnectResponse();
                }

                var result = new OpenIdConnectResponse();

                using (var tokenizer = new StringTokenizer(payload, OpenIdConnectConstants.Separators.Ampersand).GetEnumerator()) {
                    while (tokenizer.MoveNext()) {
                        var parameter = tokenizer.Current;
                        if (parameter.Length == 0) {
                            continue;
                        }

                        // Always skip the first char (# or ?).
                        if (parameter.Offset == 0) {
                            parameter = parameter.Subsegment(1, parameter.Length - 1);
                        }

                        var index = parameter.IndexOf('=');
                        if (index == -1) {
                            continue;
                        }

                        var name = parameter.Substring(0, index);
                        if (string.IsNullOrEmpty(name)) {
                            continue;
                        }

                        var value = parameter.Substring(index + 1, parameter.Length - (index + 1));
                        if (string.IsNullOrEmpty(value)) {
                            continue;
                        }

                        result.SetParameter(
                            Uri.UnescapeDataString(name.Replace('+', ' ')),
                            Uri.UnescapeDataString(value.Replace('+', ' ')));
                    }
                }

                return result;
            }

            else if (string.Equals(response.Content?.Headers?.ContentType?.MediaType, "application/json", StringComparison.OrdinalIgnoreCase)) {
                using (var stream = await response.Content.ReadAsStreamAsync())
                using (var reader = new JsonTextReader(new StreamReader(stream))) {
                    var payload = JToken.ReadFrom(reader) as JObject;
                    if (payload == null) {
                        throw new InvalidOperationException("The JSON payload returned by the server was invalid.");
                    }

                    return new OpenIdConnectResponse(payload);
                }
            }

            else if (string.Equals(response.Content?.Headers?.ContentType?.MediaType, "text/html", StringComparison.OrdinalIgnoreCase)) {
                using (var stream = await response.Content.ReadAsStreamAsync()) {
                    var result = new OpenIdConnectResponse();

                    var document = await new HtmlParser().ParseAsync(stream);

                    foreach (var element in document.Body.GetElementsByTagName("input")) {
                        var name = element.GetAttribute("name");
                        if (string.IsNullOrEmpty(name)) {
                            continue;
                        }

                        var value = element.GetAttribute("value");
                        if (string.IsNullOrEmpty(value)) {
                            continue;
                        }

                        result.SetParameter(name, value);
                    }

                    return result;
                }
            }

            else if (string.Equals(response.Content?.Headers?.ContentType?.MediaType, "text/plain", StringComparison.OrdinalIgnoreCase)) {
                using (var stream = await response.Content.ReadAsStreamAsync())
                using (var reader = new StreamReader(stream)) {
                    var result = new OpenIdConnectResponse();

                    for (var line = await reader.ReadLineAsync(); line != null; line = await reader.ReadLineAsync()) {
                        var index = line.IndexOf(':');
                        if (index == -1) {
                            continue;
                        }

                        result.SetParameter(line.Substring(0, index), line.Substring(index + 1));
                    }

                    return result;
                }
            }

            throw new InvalidOperationException("The server returned an unexpected response.");
        }
    }
}
