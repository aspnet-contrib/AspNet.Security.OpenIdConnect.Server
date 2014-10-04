using System;
using System.Linq;
using System.Reflection;
using System.Web.Mvc;

namespace Mvc.Server.Extensions {
    public class ConditionalRouteAttribute : ActionMethodSelectorAttribute {
        public ConditionalRouteAttribute(string parameter) {
            Parameter = parameter;
        }

        public string Parameter { get; private set; }

        public override bool IsValidForRequest(ControllerContext controllerContext, MethodInfo methodInfo) {
            // Returns true if the required parameter can be found in the request body.
            return (from parameter in controllerContext.HttpContext.Request.Form.Keys.OfType<string>()
                    where string.Equals(parameter, Parameter, StringComparison.OrdinalIgnoreCase)
                    select parameter).Any();
        }
    }
}