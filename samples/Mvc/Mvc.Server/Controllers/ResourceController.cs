using Microsoft.AspNet.Mvc;

namespace Mvc.Server.Controllers {
    public class ResourceController : Controller {
        [HttpGet("identity")]
        public ActionResult GetIdentity() {
            return Content(Context.User?.Identity?.Name);
        }
    }
}