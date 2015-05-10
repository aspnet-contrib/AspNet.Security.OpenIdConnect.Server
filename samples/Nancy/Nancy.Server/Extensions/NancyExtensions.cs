using System;
using System.IO;
using Microsoft.IdentityModel.Protocols;
using Microsoft.Owin;
using Nancy.Owin;
using Nancy.Session;

namespace Nancy.Server.Extensions {
    public static class NancyExtensions {
        public static IOwinContext GetOwinContext(this NancyContext context) {
            if (context == null) {
                throw new ArgumentNullException("context");
            }

            var environment = context.GetOwinEnvironment();
            if (environment == null) {
                throw new InvalidOperationException("The OWIN environment cannot be extracted from NancyContext");
            }

            return new OwinContext(environment);
        }

        public static OpenIdConnectMessage GetOpenIdConnectRequest(this ISession session, string key) {
            if (session == null) {
                throw new ArgumentNullException("session");
            }

            var item = session[key] as string;
            if (item == null) {
                return null;
            }

            using (var stream = new MemoryStream(Convert.FromBase64String(item)))
            using (var reader = new BinaryReader(stream)) {
                var version = reader.ReadInt32();
                if (version != 1) {
                    session.Delete(key);

                    return null;
                }

                var request = new OpenIdConnectMessage();
                var length = reader.ReadInt32();

                for (var index = 0; index < length; index++) {
                    var name = reader.ReadString();
                    var value = reader.ReadString();

                    request.SetParameter(name, value);
                }

                return request;
            }
        }

        public static void SetOpenIdConnectRequest(this ISession session, string key, OpenIdConnectMessage request) {
            if (session == null) {
                throw new ArgumentNullException("session");
            }

            if (request == null) {
                session.Delete(key);

                return;
            }

            using (var stream = new MemoryStream())
            using (var writer = new BinaryWriter(stream)) {
                writer.Write(/* version: */ 1);
                writer.Write(request.Parameters.Count);

                foreach (var parameter in request.Parameters) {
                    writer.Write(parameter.Key);
                    writer.Write(parameter.Value);
                }

                session[key] = Convert.ToBase64String(stream.ToArray());
            }
        }
    }
}