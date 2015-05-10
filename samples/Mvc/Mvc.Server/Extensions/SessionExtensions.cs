using System;
using System.IO;
using System.Web;
using Microsoft.IdentityModel.Protocols;

namespace Mvc.Server.Extensions {
    public static class SessionExtensions {
        public static OpenIdConnectMessage GetOpenIdConnectRequest(this HttpSessionStateBase session, string key) {
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
                    session.Remove(key);

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

        public static void SetOpenIdConnectRequest(this HttpSessionStateBase session, string key, OpenIdConnectMessage request) {
            if (session == null) {
                throw new ArgumentNullException("session");
            }

            if (request == null) {
                session.Remove(key);

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

                session.Add(key, Convert.ToBase64String(stream.ToArray()));
            }
        }
    }
}