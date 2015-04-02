using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Mvc;
using Microsoft.IdentityModel.Protocols;

namespace Mvc.Client.Controllers {
    public class HomeController : Controller {
        [HttpGet, Route("~/")]
        public ActionResult Index() {
            return View("Home");
        }

        [Authorize, HttpPost, Route("~/")]
        public async Task<ActionResult> Index(CancellationToken cancellationToken) {
            using (var client = new HttpClient()) {
                var request = new HttpRequestMessage(HttpMethod.Get, "http://localhost:54540/api/message");
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", AccessToken);

                var response = await client.SendAsync(request, cancellationToken);
                response.EnsureSuccessStatusCode();

                return View("Home", model: await response.Content.ReadAsStringAsync());
            }
        }

        protected ClaimsPrincipal Principal {
            get { return User as ClaimsPrincipal ?? new ClaimsPrincipal(User); }
        }

        protected string AccessToken {
            get {
                var claim = Principal.FindFirst(OpenIdConnectParameterNames.AccessToken);
                if (claim == null) {
                    throw new InvalidOperationException();
                }

                return claim.Value;
            }
        }
    }
}