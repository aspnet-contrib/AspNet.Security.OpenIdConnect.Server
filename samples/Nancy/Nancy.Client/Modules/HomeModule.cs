using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Nancy.Security;

namespace Nancy.Client.Modules
{
    public class HomeModule : NancyModule
    {
        public HomeModule()
        {
            Get["/"] = parameters =>
            {
                return View["home.cshtml"];
            };

            Post["/", runAsync: true] = async (parameters, cancellationToken) =>
            {
                this.RequiresMSOwinAuthentication();

                using (var client = new HttpClient())
                {
                    var request = new HttpRequestMessage(HttpMethod.Get, "http://localhost:54541/api/message");
                    request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", AccessToken);

                    var response = await client.SendAsync(request, cancellationToken);
                    response.EnsureSuccessStatusCode();

                    return View["home.cshtml", await response.Content.ReadAsStringAsync()];
                }
            };
        }

        private ClaimsPrincipal Principal => Context.GetMSOwinUser();

        private string AccessToken
        {
            get
            {
                var claim = Principal.FindFirst(OpenIdConnectParameterNames.AccessToken);
                if (claim == null)
                {
                    throw new InvalidOperationException();
                }

                return claim.Value;
            }
        }
    }
}
