using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;

#if DNX451
using Microsoft.Owin.Builder;
using Microsoft.Owin.BuilderProperties;
using Owin;
#endif

namespace Mvc.Server.Extensions {
    public static class AppBuilderExtensions {
        public static IApplicationBuilder UseWhen(this IApplicationBuilder app,
            Func<HttpContext, bool> condition, Action<IApplicationBuilder> configuration) {
            if (app == null) {
                throw new ArgumentNullException(nameof(app));
            }

            if (condition == null) {
                throw new ArgumentNullException(nameof(condition));
            }

            if (configuration == null) {
                throw new ArgumentNullException(nameof(configuration));
            }

            var builder = app.New();
            configuration(builder);

            return app.Use(next => {
                builder.Run(next);

                var branch = builder.Build();

                return context => {
                    if (condition(context)) {
                        return branch(context);
                    }

                    return next(context);
                };
            });
        }

#if DNX451
        public static IApplicationBuilder UseOwinAppBuilder(this IApplicationBuilder app, Action<IAppBuilder> configuration) {
            if (app == null) {
                throw new ArgumentNullException(nameof(app));
            }

            if (configuration == null) {
                throw new ArgumentNullException(nameof(configuration));
            }

            return app.UseOwin(setup => setup(next => {
                var builder = new AppBuilder();
                var lifetime = (IApplicationLifetime) app.ApplicationServices.GetService(typeof(IApplicationLifetime));

                var properties = new AppProperties(builder.Properties);
                properties.AppName = app.ApplicationServices.GetApplicationUniqueIdentifier();
                properties.OnAppDisposing = lifetime.ApplicationStopping;
                properties.DefaultApp = next;

                configuration(builder);

                return builder.Build<Func<IDictionary<string, object>, Task>>();
            }));
        }
#endif
    }
}