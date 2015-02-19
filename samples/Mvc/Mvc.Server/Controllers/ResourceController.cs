using System.Globalization;
using System.Linq;
using Microsoft.AspNet.Mvc;
using Microsoft.AspNet.Security;

namespace Mvc.Server.Controllers {
    [Route("api")]
    public class ResourceController : Controller {
        [Authorize, HttpGet("claims")]
        public ActionResult GetClaims() {
            return Json(
                from claim in Context.User.Claims
                select new {
                    claim.Type, claim.Value,
                    claim.ValueType, claim.Issuer });
        }

        [Authorize, HttpGet("message")]
        public ActionResult GetMessage() {
            return Content(string.Format(
                CultureInfo.InvariantCulture,
                "Hello {0}!",
                User.Identity.Name));
        }
    }
}