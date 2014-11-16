using System.Linq;
using Microsoft.AspNet.Mvc;

namespace Mvc.Server.Controllers {
    public class ResourceController : Controller {
        [Authorize, HttpGet("claims")]
        public ActionResult GetClaims() {
            return Json(
                from claim in Context.User.Claims
                select new {
                    claim.Type, claim.Value,
                    claim.ValueType, claim.Issuer });
        }
    }
}