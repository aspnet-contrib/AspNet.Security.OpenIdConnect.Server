using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Owin;

namespace Nancy.Server.Extensions
{
    public static class OwinExtensions
    {
        public static IEnumerable<AuthenticationDescription> GetExternalProviders(this IAuthenticationManager manager)
        {
            if (manager == null)
            {
                throw new ArgumentNullException("manager");
            }

            return from description in manager.GetAuthenticationTypes()
                   where !string.IsNullOrEmpty(description.Caption)
                   select description;
        }

        public static bool IsProviderSupported(this IAuthenticationManager manager, string provider)
        {
            if (manager == null)
            {
                throw new ArgumentNullException("manager");
            }

            return (from description in manager.GetExternalProviders()
                    where string.Equals(description.AuthenticationType, provider, StringComparison.OrdinalIgnoreCase)
                    select description).Any();
        }

        public static T Build<T>(this IAppBuilder app)
        {
            if (app == null)
            {
                throw new ArgumentNullException("app");
            }

            return (T) app.Build(typeof(T));
        }

        public static IAppBuilder UseWhen(this IAppBuilder app,
            Func<IOwinContext, bool> condition, Action<IAppBuilder> configuration)
        {
            if (app == null)
            {
                throw new ArgumentNullException("app");
            }

            if (condition == null)
            {
                throw new ArgumentNullException("condition");
            }

            if (configuration == null)
            {
                throw new ArgumentNullException("configuration");
            }

            return app.Use((context, next) =>
            {
                if (condition(context))
                {
                    var builder = app.New();
                    configuration(builder);
                    builder.Run(_ => next());

                    var branch = builder.Build<Func<IDictionary<string, object>, Task>>();
                    return branch(context.Environment);
                }

                return next();
            });
        }
    }
}
