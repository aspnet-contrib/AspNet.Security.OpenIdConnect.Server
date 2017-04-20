using System.Security.Claims;
using AspNet.Security.OAuth.Validation;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Mvc.Server.Controllers
{
    [Authorize(AuthenticationSchemes = OAuthValidationDefaults.AuthenticationScheme)]
    [Route("api")]
    public class ResourceController : Controller
    {
        [HttpGet, Route("message")]
        public IActionResult GetMessage()
        {
            var identity = User.Identity as ClaimsIdentity;
            if (identity == null)
            {
                return BadRequest();
            }

            return Content($"{identity.Name} has been successfully authenticated.");
        }
    }
}
