using System.IO;
using Microsoft.Owin.Security.DataHandler.Serializer;

namespace Microsoft.Owin.Security.OpenIdConnect.Server {
    public class OpenIdConnectPayloadSerializer : IDataSerializer<OpenIdConnectPayload> {
        public const int Version = 1;

        public static readonly OpenIdConnectPayloadSerializer Instance = new OpenIdConnectPayloadSerializer();

        public OpenIdConnectPayload Deserialize(byte[] data) {
            using (var stream = new MemoryStream(data))
            using (var reader = new BinaryReader(stream)) {
                if (reader.ReadInt32() != Version) {
                    return null;
                }

                int count = reader.ReadInt32();
                var payload = new OpenIdConnectPayload(count);

                for (var index = 0; index != count; ++index) {
                    string key = reader.ReadString();
                    string value = reader.ReadString();

                    payload.Add(key, value);
                }

                return payload;
            }
        }

        public byte[] Serialize(OpenIdConnectPayload model) {
            using (var stream = new MemoryStream())
            using (var writer = new BinaryWriter(stream)) {
                writer.Write(Version);
                writer.Write(model.Count);

                foreach (var element in model) {
                    writer.Write(element.Key);
                    writer.Write(element.Value);
                }

                writer.Flush();
                return stream.ToArray();
            }
        }
    }
}
