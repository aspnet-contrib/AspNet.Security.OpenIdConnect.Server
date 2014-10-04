using System.Web.Mvc;

namespace Mvc.Server.Controllers {
    public class HomeController : Controller {
        [HttpGet, Route("~/")]
        public ActionResult Index() {
            return Content("OpenID Connect server started.");
        }
    }
}