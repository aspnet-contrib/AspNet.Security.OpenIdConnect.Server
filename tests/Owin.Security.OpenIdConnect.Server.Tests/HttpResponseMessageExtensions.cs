using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Formatting;
using System.Threading.Tasks;
using System.Xml.Linq;
using System.Xml.XPath;
using Microsoft.IdentityModel.Protocols;
using Newtonsoft.Json.Linq;
using Owin.Security.OpenIdConnect.Extensions;

namespace Owin.Security.OpenIdConnect.Server.Tests {
    internal static class HttpResponseMessageExtensions {
        public static async Task<OpenIdConnectMessage> ReadAsOpenIdConnectMessageAsync(this HttpResponseMessage response) {
            if (response == null) {
                throw new ArgumentNullException(nameof(response));
            }

            switch (response.StatusCode) {
                case HttpStatusCode.BadRequest:
                case HttpStatusCode.OK:
                    return await response.Content.GetOpenIdMessageFromBodyAsync();

                case HttpStatusCode.Found:
                    var request = (OpenIdConnectMessage)response.RequestMessage.Properties["oidc_req"];
                    return response.Headers.Location.GetOpenIdMessageFromUri(request.IsFragmentResponseMode());

                default:
                    throw new NotImplementedException($"Unable to handle response status {response.StatusCode}");
            }
        }

        private static async Task<OpenIdConnectMessage> GetOpenIdMessageFromBodyAsync(this HttpContent content) {
            if (content == null) {
                throw new ArgumentNullException(nameof(content));
            }

            var responseString = await content.ReadAsStringAsync();

            switch (content.Headers.ContentType.MediaType) {
                case "application/json":
                    return GetOpenIdMessageFromJson(JToken.Parse(responseString));
                case "text/plain":
                    return GetOpenIdMessageFromText(responseString);
                case "text/html":
                    return GetOpenIdMessageFromHtml(responseString);

                default:
                    throw new NotImplementedException($"Unable to parse {content.Headers.ContentType.MediaType}");
            }
        }

        private static OpenIdConnectMessage GetOpenIdMessageFromHtml(string htmlResponse) {
            var html = XElement.Parse(htmlResponse.Substring(htmlResponse.IndexOf(Environment.NewLine, StringComparison.Ordinal)));

            var responseValues = html.XPathSelectElements("./body/form/input[@type='hidden' and @name and @value]")
                .Select(node => new { Name = node.Attribute("name").Value, Value = node.Attribute("value").Value });

            var response = new OpenIdConnectMessage();
            foreach (var responseValue in responseValues ) {
                response.Parameters.Add(responseValue.Name, responseValue.Value);
            }

            return response;
        }

        private static OpenIdConnectMessage GetOpenIdMessageFromText(string textResponse) {
            var response = new OpenIdConnectMessage();
            foreach (var line in textResponse.Split(new[] {Environment.NewLine}, StringSplitOptions.RemoveEmptyEntries)) {
                if (!string.IsNullOrEmpty(line)) {
                    var colonIndex = line.IndexOf(':');
                    if (colonIndex > 0) {
                        response.Parameters.Add(line.Substring(0, colonIndex).Trim(), line.Substring(colonIndex + 1).Trim());
                    }
                }
            }

            return response;
        }

        private static OpenIdConnectMessage GetOpenIdMessageFromJson(JToken jsonResponse) {
            var responseData = new NameValueCollection();

            foreach (var keyPair in jsonResponse.ToObject<Dictionary<string, string>>()) {
                responseData[keyPair.Key] = keyPair.Value;
            }

            return new OpenIdConnectMessage(responseData);
        }

        private static OpenIdConnectMessage GetOpenIdMessageFromUri(this Uri uri, bool useFragment) {
            if (uri == null) {
                throw new ArgumentNullException(nameof(uri));
            }

            var responseData = useFragment ?
                new FormDataCollection(uri.Fragment.Length > 0 ? uri.Fragment.Substring(1) : uri.Fragment).ReadAsNameValueCollection() :
                uri.ParseQueryString();

            return new OpenIdConnectMessage(responseData);
        }
    }
}