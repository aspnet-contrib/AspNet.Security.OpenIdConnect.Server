using System;
using System.Data.Entity;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Owin.Security.Infrastructure;
using Nancy.Server.Models;

namespace Nancy.Server.Providers {
    public class AuthorizationCodeProvider : AuthenticationTokenProvider {
        public override async Task CreateAsync(AuthenticationTokenCreateContext context) {
            using (var db = new ApplicationContext()) {
                // Create a new unique identifier that will be used to replace the authorization code serialized
                // by AuthenticationTokenCreateContext.SerializeTicket() during the code/token exchange process.
                // Note: while you can replace the generation mechanism, you MUST ensure your custom algorithm
                // generates unpredictable identifiers to guarantee a correct entropy.

                string nonceID = Guid.NewGuid().ToString();

                var nonce = new Nonce {
                    NonceID = nonceID,
                    Ticket = context.SerializeTicket()
                };

                db.Nonces.Add(nonce);
                await db.SaveChangesAsync(context.Request.CallCancelled);

                context.SetToken(nonceID);
            }
        }

        public override async Task ReceiveAsync(AuthenticationTokenReceiveContext context) {
            using (var db = new ApplicationContext()) {
                // Retrieve the authorization code serialized by AuthenticationTokenCreateContext.SerializeTicket
                // using the nonce identifier generated in CreateAsync and returned to the client application.
                // Note: you MUST ensure the nonces are correctly removed after each call to prevent replay attacks.
                string nonceID = context.Token;

                Nonce nonce = await (from entity in db.Nonces
                                     where entity.NonceID == nonceID
                                     select entity).SingleOrDefaultAsync(context.Request.CallCancelled);

                if (nonce == null) {
                    return;
                }

                db.Nonces.Remove(nonce);
                await db.SaveChangesAsync(context.Request.CallCancelled);

                context.DeserializeTicket(nonce.Ticket);
            }
        }
    }
}
