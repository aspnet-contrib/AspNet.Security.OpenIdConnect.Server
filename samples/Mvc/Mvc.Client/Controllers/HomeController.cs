using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;
using Microsoft.AspNet.Mvc;

namespace Mvc.Client.Controllers {
    public class HomeController : Controller {
        [HttpGet("~/")]
        public async Task<ActionResult> Index() {
            var principal = Context.User;

            // Determine whether the user agent has been successfully authenticated
            // by the cookies middleware (configured with AuthenticationMode.Active in Startup.cs)
            if (principal == null || principal.Identity == null || !principal.Identity.IsAuthenticated) {
                return View("Home", null);
            }

            using (var client = new HttpClient()) {
                var token = principal.FindFirst("access_token");
                if (token == null) {
                    return View("Home", null);
                }

                client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token.Value);

                return View("Home", await client.GetStringAsync("http://localhost:54540/api/identity"));
            }
        }
    }
}