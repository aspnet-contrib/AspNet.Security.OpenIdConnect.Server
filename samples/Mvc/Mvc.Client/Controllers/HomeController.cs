using System.Security.Claims;
using System.Web.Mvc;

namespace Mvc.Client.Controllers {
    public class HomeController : Controller {
        [HttpGet, Route("~/")]
        public ActionResult Index() {
            var principal = User as ClaimsPrincipal;

            // Determine whether the user agent has been successfully authenticated
            // by the cookies middleware (configured with AuthenticationMode.Active in Startup.cs)
            if (principal == null || principal.Identity == null || !principal.Identity.IsAuthenticated) {
                principal = null;
            }

            return View("Home", principal);
        }
    }
}