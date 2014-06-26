using Microsoft.AspNet.Mvc;

namespace Mvc.Server.Controllers {
    public class HomeController : Controller {
        [HttpGet("~/")]
        public ActionResult Index() {
            return Content("OpenID Connect server started.");
        }
    }
}