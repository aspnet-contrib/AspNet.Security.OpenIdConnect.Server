using System.Globalization;
using System.Net;
using System.Security.Claims;
using System.Web.Http;

namespace Mvc.Server.Controllers {
    public class ResourceController : ApiController {
        [Authorize, HttpGet, Route("message")]
        public IHttpActionResult GetMessage() {
            var identity = User.Identity as ClaimsIdentity;
            if (identity == null) {
                return InternalServerError();
            }

            // Note: identity is the ClaimsIdentity representing the resource owner
            // and identity.Actor is the identity corresponding to the client
            // application the access token has been issued to (delegation).
            return Content(HttpStatusCode.OK, string.Format(
                CultureInfo.InvariantCulture,
                "{0} has been successfully authenticated via {1}",
                identity.Name, identity.Actor.Name));
        }
    }
}
