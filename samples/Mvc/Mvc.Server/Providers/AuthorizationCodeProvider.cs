using System;
using System.Linq;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Server;
using Microsoft.AspNet.Authentication;
using Microsoft.Data.Entity;
using Microsoft.Framework.DependencyInjection;
using Microsoft.Framework.OptionsModel;
using Mvc.Server.Models;

namespace Mvc.Server.Providers {
    public class AuthorizationCodeProvider : AuthenticationTokenProvider {
        public override async Task CreateAsync(AuthenticationTokenCreateContext context) {
            var database = context.HttpContext.RequestServices.GetRequiredService<ApplicationContext>();

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

        public override async Task ReceiveAsync(AuthenticationTokenReceiveContext context) {
            var database = context.HttpContext.RequestServices.GetRequiredService<ApplicationContext>();

            // Retrieve the authorization code serialized by AuthenticationTokenCreateContext.SerializeTicket
            // using the nonce identifier generated in CreateAsync and returned to the client application.
            // Note: you MUST ensure the nonces are correctly removed after each call to prevent replay attacks.
            string nonceID = context.Token;

            var nonce = await (from entity in database.Nonces
                               where entity.NonceID == nonceID
                               select entity).SingleOrDefaultAsync(context.HttpContext.RequestAborted);

            if (nonce == null) {
                return;
            }

            database.Nonces.Remove(nonce);
            await database.SaveChangesAsync(context.HttpContext.RequestAborted);

            // Retrieve the authorization code format from the options.
            var options = context.HttpContext.RequestServices.GetRequiredService<IOptions<OpenIdConnectServerOptions>>();

            context.SetTicket(options.Options.AuthorizationCodeFormat.Unprotect(nonce.Ticket));
        }
    }
}
