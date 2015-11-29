using System.Security.Claims;
using Microsoft.AspNet.Authorization;
using Microsoft.AspNet.Mvc;

namespace Mvc.Server.Controllers {
    [Route("api")]
    public class ResourceController : Controller {
        [Authorize, HttpGet, Route("message")]
        public IActionResult GetMessage() {
            var identity = User.Identity as ClaimsIdentity;
            if (identity == null) {
                return HttpBadRequest();
            }

            return Content($"{identity.Name} has been successfully authenticated.");
        }
    }
}