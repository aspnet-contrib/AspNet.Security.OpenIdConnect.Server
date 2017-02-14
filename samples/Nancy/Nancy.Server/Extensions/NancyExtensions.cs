using System;
using Microsoft.Owin;
using Nancy.Owin;

namespace Nancy.Server.Extensions
{
    public static class NancyExtensions
    {
        public static IOwinContext GetOwinContext(this NancyContext context)
        {
            if (context == null)
            {
                throw new ArgumentNullException("context");
            }

            var environment = context.GetOwinEnvironment();
            if (environment == null)
            {
                throw new InvalidOperationException("The OWIN environment cannot be extracted from NancyContext");
            }

            return new OwinContext(environment);
        }
    }
}
