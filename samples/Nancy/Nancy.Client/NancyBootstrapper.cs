using System;
using System.Collections.Generic;
using Nancy.ViewEngines.Razor;

namespace Nancy.Client {
    public class NancyBootstrapper : DefaultNancyBootstrapper {
        protected override IEnumerable<Type> ViewEngines {
            get {
                yield return typeof(RazorViewEngine);
            }
        }
    }
}