using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.AspNet.Builder;
using Microsoft.AspNet.Hosting;
using Microsoft.AspNet.Http;
using Microsoft.Owin.Builder;
using Microsoft.Owin.BuilderProperties;
using Owin;

namespace Mvc.Server.Extensions {
    using AppFunc = Func<IDictionary<string, object>, Task>;

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

            return app.Use(next => {
                configuration(builder);
                builder.Use(_ => context => next(context));

                var branch = builder.Build();

                return context => {
                    if (condition(context)) {
                        return branch(context);
                    }

                    return next(context);
                };
            });
        }

#if ASPNET50
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
                properties.AppName = app.Server.Name;
                properties.OnAppDisposing = lifetime.ApplicationStopping;
                properties.DefaultApp = next;

                configuration(builder);

                return builder.Build<AppFunc>();
            }));
        }
#endif
    }
}