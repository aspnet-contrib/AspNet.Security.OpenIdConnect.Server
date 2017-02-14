/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using AngleSharp.Parser.Html;
using AspNet.Security.OpenIdConnect.Primitives;
using JetBrains.Annotations;
using Microsoft.Extensions.Primitives;
using Newtonsoft.Json;

namespace AspNet.Security.OpenIdConnect.Client
{
    /// <summary>
    /// Exposes methods that allow sending OpenID Connect
    /// requests and extracting the corresponding responses.
    /// </summary>
    public class OpenIdConnectClient
    {
        /// <summary>
        /// Initializes a new instance of the OpenID Connect client.
        /// </summary>
        public OpenIdConnectClient()
        {
            HttpClient = new HttpClient();
        }

        /// <summary>
        /// Initializes a new instance of the OpenID Connect client.
        /// </summary>
        /// <param name="client">The HTTP client used to communicate with the OpenID Connect server.</param>
        public OpenIdConnectClient([NotNull] HttpClient client)
        {
            if (client == null)
            {
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
        /// <param name="uri">The endpoint to which the request is sent.</param>
        /// <returns>The OpenID Connect response returned by the server.</returns>
        public Task<OpenIdConnectResponse> GetAsync([NotNull] string uri)
        {
            return GetAsync(uri, new OpenIdConnectRequest());
        }

        /// <summary>
        /// Sends an empty OpenID Connect request to the given endpoint using GET
        /// and converts the returned response to an OpenID Connect response.
        /// </summary>
        /// <param name="uri">The endpoint to which the request is sent.</param>
        /// <returns>The OpenID Connect response returned by the server.</returns>
        public Task<OpenIdConnectResponse> GetAsync([NotNull] Uri uri)
        {
            return GetAsync(uri, new OpenIdConnectRequest());
        }

        /// <summary>
        /// Sends a generic OpenID Connect request to the given endpoint using GET
        /// and converts the returned response to an OpenID Connect response.
        /// </summary>
        /// <param name="uri">The endpoint to which the request is sent.</param>
        /// <param name="request">The OpenID Connect request to send.</param>
        /// <returns>The OpenID Connect response returned by the server.</returns>
        public Task<OpenIdConnectResponse> GetAsync(
            [NotNull] string uri, [NotNull] OpenIdConnectRequest request)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            if (string.IsNullOrEmpty(uri))
            {
                throw new ArgumentException("The URL cannot be null or empty.", nameof(uri));
            }

            return GetAsync(new Uri(uri, UriKind.RelativeOrAbsolute), request);
        }

        /// <summary>
        /// Sends a generic OpenID Connect request to the given endpoint using GET
        /// and converts the returned response to an OpenID Connect response.
        /// </summary>
        /// <param name="uri">The endpoint to which the request is sent.</param>
        /// <param name="request">The OpenID Connect request to send.</param>
        /// <returns>The OpenID Connect response returned by the server.</returns>
        public Task<OpenIdConnectResponse> GetAsync(
            [NotNull] Uri uri, [NotNull] OpenIdConnectRequest request)
        {
            return SendAsync(HttpMethod.Get, uri, request);
        }

        /// <summary>
        /// Sends a generic OpenID Connect request to the given endpoint using POST
        /// and converts the returned response to an OpenID Connect response.
        /// </summary>
        /// <param name="uri">The endpoint to which the request is sent.</param>
        /// <param name="request">The OpenID Connect request to send.</param>
        /// <returns>The OpenID Connect response returned by the server.</returns>
        public Task<OpenIdConnectResponse> PostAsync(
            [NotNull] string uri, [NotNull] OpenIdConnectRequest request)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            if (string.IsNullOrEmpty(uri))
            {
                throw new ArgumentException("The URL cannot be null or empty.", nameof(uri));
            }

            return PostAsync(new Uri(uri, UriKind.RelativeOrAbsolute), request);
        }

        /// <summary>
        /// Sends a generic OpenID Connect request to the given endpoint using POST
        /// and converts the returned response to an OpenID Connect response.
        /// </summary>
        /// <param name="uri">The endpoint to which the request is sent.</param>
        /// <param name="request">The OpenID Connect request to send.</param>
        /// <returns>The OpenID Connect response returned by the server.</returns>
        public Task<OpenIdConnectResponse> PostAsync(
            [NotNull] Uri uri, [NotNull] OpenIdConnectRequest request)
        {
            return SendAsync(HttpMethod.Post, uri, request);
        }

        /// <summary>
        /// Sends a generic OpenID Connect request to the given endpoint and
        /// converts the returned response to an OpenID Connect response.
        /// </summary>
        /// <param name="method">The HTTP method used to send the OpenID Connect request.</param>
        /// <param name="uri">The endpoint to which the request is sent.</param>
        /// <param name="request">The OpenID Connect request to send.</param>
        /// <returns>The OpenID Connect response returned by the server.</returns>
        public Task<OpenIdConnectResponse> SendAsync(
            [NotNull] string method, [NotNull] string uri,
            [NotNull] OpenIdConnectRequest request)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            if (string.IsNullOrEmpty(method))
            {
                throw new ArgumentException("The HTTP method cannot be null or empty.", nameof(method));
            }

            if (string.IsNullOrEmpty(uri))
            {
                throw new ArgumentException("The URL cannot be null or empty.", nameof(uri));
            }

            return SendAsync(new HttpMethod(method), uri, request);
        }

        /// <summary>
        /// Sends a generic OpenID Connect request to the given endpoint and
        /// converts the returned response to an OpenID Connect response.
        /// </summary>
        /// <param name="method">The HTTP method used to send the OpenID Connect request.</param>
        /// <param name="uri">The endpoint to which the request is sent.</param>
        /// <param name="request">The OpenID Connect request to send.</param>
        /// <returns>The OpenID Connect response returned by the server.</returns>
        public Task<OpenIdConnectResponse> SendAsync(
            [NotNull] HttpMethod method, [NotNull] string uri,
            [NotNull] OpenIdConnectRequest request)
        {
            if (method == null)
            {
                throw new ArgumentNullException(nameof(method));
            }

            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            if (string.IsNullOrEmpty(uri))
            {
                throw new ArgumentException("The URL cannot be null or empty.", nameof(uri));
            }

            return SendAsync(method, new Uri(uri, UriKind.RelativeOrAbsolute), request);
        }

        /// <summary>
        /// Sends a generic OpenID Connect request to the given endpoint and
        /// converts the returned response to an OpenID Connect response.
        /// </summary>
        /// <param name="method">The HTTP method used to send the OpenID Connect request.</param>
        /// <param name="uri">The endpoint to which the request is sent.</param>
        /// <param name="request">The OpenID Connect request to send.</param>
        /// <returns>The OpenID Connect response returned by the server.</returns>
        public virtual async Task<OpenIdConnectResponse> SendAsync(
            [NotNull] HttpMethod method, [NotNull] Uri uri,
            [NotNull] OpenIdConnectRequest request)
        {
            if (method == null)
            {
                throw new ArgumentNullException(nameof(method));
            }

            if (uri == null)
            {
                throw new ArgumentNullException(nameof(uri));
            }

            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            if (HttpClient.BaseAddress == null && !uri.IsAbsoluteUri)
            {
                throw new ArgumentException("The address cannot be a relative URI when no base address " +
                                            "is associated with the HTTP client.", nameof(uri));
            }

            var parameters = new Dictionary<string, string>();

            foreach (var parameter in request.GetParameters())
            {
                var value = (string) parameter.Value;
                if (string.IsNullOrEmpty(value))
                {
                    continue;
                }

                parameters.Add(parameter.Key, value);
            }

            if (method == HttpMethod.Get && parameters.Count != 0)
            {
                var builder = new StringBuilder();

                foreach (var parameter in parameters)
                {
                    if (builder.Length != 0)
                    {
                        builder.Append('&');
                    }

                    builder.Append(UrlEncoder.Default.Encode(parameter.Key));
                    builder.Append('=');
                    builder.Append(UrlEncoder.Default.Encode(parameter.Value));
                }

                if (!uri.IsAbsoluteUri)
                {
                    uri = new Uri(HttpClient.BaseAddress, uri);
                }

                uri = new UriBuilder(uri) { Query = builder.ToString() }.Uri;
            }

            var message = new HttpRequestMessage(method, uri);

            if (method != HttpMethod.Get)
            {
                message.Content = new FormUrlEncodedContent(parameters);
            }

            var response = await HttpClient.SendAsync(message, HttpCompletionOption.ResponseHeadersRead);

            if (response.Headers.Location != null)
            {
                var payload = response.Headers.Location.Fragment;
                if (string.IsNullOrEmpty(payload))
                {
                    payload = response.Headers.Location.Query;
                }

                if (string.IsNullOrEmpty(payload))
                {
                    return new OpenIdConnectResponse();
                }

                var result = new OpenIdConnectResponse();

                using (var tokenizer = new StringTokenizer(payload, OpenIdConnectConstants.Separators.Ampersand).GetEnumerator())
                {
                    while (tokenizer.MoveNext())
                    {
                        var parameter = tokenizer.Current;
                        if (parameter.Length == 0)
                        {
                            continue;
                        }

                        // Always skip the first char (# or ?).
                        if (parameter.Offset == 0)
                        {
                            parameter = parameter.Subsegment(1, parameter.Length - 1);
                        }

                        var index = parameter.IndexOf('=');
                        if (index == -1)
                        {
                            continue;
                        }

                        var name = parameter.Substring(0, index);
                        if (string.IsNullOrEmpty(name))
                        {
                            continue;
                        }

                        var value = parameter.Substring(index + 1, parameter.Length - (index + 1));
                        if (string.IsNullOrEmpty(value))
                        {
                            continue;
                        }

                        result.AddParameter(
                            Uri.UnescapeDataString(name.Replace('+', ' ')),
                            Uri.UnescapeDataString(value.Replace('+', ' ')));
                    }
                }

                return result;
            }

            else if (string.Equals(response.Content?.Headers?.ContentType?.MediaType, "application/json", StringComparison.OrdinalIgnoreCase))
            {
                using (var stream = await response.Content.ReadAsStreamAsync())
                using (var reader = new JsonTextReader(new StreamReader(stream)))
                {
                    var serializer = JsonSerializer.CreateDefault();

                    return serializer.Deserialize<OpenIdConnectResponse>(reader);
                }
            }

            else if (string.Equals(response.Content?.Headers?.ContentType?.MediaType, "text/html", StringComparison.OrdinalIgnoreCase))
            {
                using (var stream = await response.Content.ReadAsStreamAsync())
                {
                    var result = new OpenIdConnectResponse();

                    var document = await new HtmlParser().ParseAsync(stream);

                    foreach (var element in document.Body.GetElementsByTagName("input"))
                    {
                        var name = element.GetAttribute("name");
                        if (string.IsNullOrEmpty(name))
                        {
                            continue;
                        }

                        var value = element.GetAttribute("value");
                        if (string.IsNullOrEmpty(value))
                        {
                            continue;
                        }

                        result.AddParameter(name, value);
                    }

                    return result;
                }
            }

            else if (string.Equals(response.Content?.Headers?.ContentType?.MediaType, "text/plain", StringComparison.OrdinalIgnoreCase))
            {
                using (var stream = await response.Content.ReadAsStreamAsync())
                using (var reader = new StreamReader(stream))
                {
                    var result = new OpenIdConnectResponse();

                    for (var line = await reader.ReadLineAsync(); line != null; line = await reader.ReadLineAsync())
                    {
                        var index = line.IndexOf(':');
                        if (index == -1)
                        {
                            continue;
                        }

                        result.AddParameter(line.Substring(0, index), line.Substring(index + 1));
                    }

                    return result;
                }
            }

            throw new InvalidOperationException("The server returned an unexpected response.");
        }
    }
}
