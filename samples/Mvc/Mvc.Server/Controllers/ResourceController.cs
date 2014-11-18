using System.Globalization;
using System.Net;
using System.Web.Http;

namespace Mvc.Server.Controllers {
    public class ResourceController : ApiController {
        [Authorize, HttpGet, Route("message")]
        public IHttpActionResult GetMessage() {
            return Content(HttpStatusCode.OK, string.Format(
                CultureInfo.InvariantCulture,
                "Hello {0}!",
                User.Identity.Name));
        }
    }
}
