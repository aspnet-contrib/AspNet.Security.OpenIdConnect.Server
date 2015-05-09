using System;
using System.Collections.Generic;
using Nancy.Bootstrapper;
using Nancy.Cryptography;
using Nancy.Security;
using Nancy.Session;
using Nancy.TinyIoc;
using Nancy.ViewEngines.Razor;

namespace Nancy.Server {
    public class NancyBootstrapper : DefaultNancyBootstrapper {
        protected override void ApplicationStartup(TinyIoCContainer container, IPipelines pipelines) {
            // Enable CSRF protection at the pipeline level
            // to be able to use it in AuthorizationModule.cs
            Csrf.Enable(pipelines);

            var salt = Convert.FromBase64String("RUc3RC12bDYxdVBFQW9TZ050NnFNNllpVTQxTDE9XkV4MXkrUGhZS0R2Nms1QWFtVmk5bFZPLTd3aWQlDQo=");
            var generator = new PassphraseKeyGenerator("Owin.Security.OpenIdConnect.Server", salt);

            CookieBasedSessions.Enable(pipelines, new CryptographyConfiguration(
                encryptionProvider: new RijndaelEncryptionProvider(generator),
                hmacProvider: new DefaultHmacProvider(generator)));

            base.ApplicationStartup(container, pipelines);
        }

        protected override IEnumerable<Type> ViewEngines {
            get {
                yield return typeof(RazorViewEngine);
            }
        }
    }
}