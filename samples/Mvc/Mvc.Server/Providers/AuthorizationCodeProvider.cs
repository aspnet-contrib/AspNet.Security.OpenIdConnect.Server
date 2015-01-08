using System;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNet.Security.Infrastructure;
using Microsoft.Framework.DependencyInjection;
using Mvc.Server.Models;

namespace Mvc.Server.Providers {
    public class AuthorizationCodeProvider : AuthenticationTokenProvider {
        private readonly IServiceScopeFactory serviceScopeFactory;

        public AuthorizationCodeProvider(IServiceScopeFactory serviceScopeFactory) {
            this.serviceScopeFactory = serviceScopeFactory;
        }

        public override async Task CreateAsync(AuthenticationTokenCreateContext context) {
            using (var scope = serviceScopeFactory.CreateScope()) {
                var database = scope.ServiceProvider.GetRequiredService<ApplicationContext>();

                // Create a new unique identifier that will be used to replace the authorization code serialized
                // by AuthenticationTokenCreateContext.SerializeTicket() during the code/token exchange process.
                // Note: while you can replace the generation mechanism, you MUST ensure your custom algorithm
                // generates unpredictable identifiers to guarantee a correct entropy.

                string nonceID = Guid.NewGuid().ToString();

                var nonce = new Nonce {
                    NonceID = nonceID,
                    Ticket = context.SerializeTicket()
                };

                database.Nonces.Add(nonce);
                await database.SaveChangesAsync(context.HttpContext.RequestAborted);

                context.SetToken(nonceID);
            }
        }

        public override async Task ReceiveAsync(AuthenticationTokenReceiveContext context) {
            using (var scope = serviceScopeFactory.CreateScope()) {
                var database = scope.ServiceProvider.GetRequiredService<ApplicationContext>();

                // Retrieve the authorization code serialized by AuthenticationTokenCreateContext.SerializeTicket
                // using the nonce identifier generated in CreateAsync and returned to the client application.
                // Note: you MUST ensure the nonces are correctly removed after each call to prevent replay attacks.
                string nonceID = context.Token;

                Nonce nonce = await (from entity in database.Nonces
                                     where entity.NonceID == nonceID
                                     select entity).SingleOrDefaultAsync(context.HttpContext.RequestAborted);

                if (nonce == null) {
                    return;
                }

                database.Nonces.Remove(nonce);
                await database.SaveChangesAsync(context.HttpContext.RequestAborted);

                context.DeserializeTicket(nonce.Ticket);
            }
        }
    }
}
