/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/AspNet-OpenIdConnect-Server/Owin.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.Threading.Tasks;

namespace AspNet.Security.OpenIdConnect.Server {
    internal static class DefaultBehavior {
        internal static readonly Func<OpenIdConnectValidateAuthorizationRequestContext, Task> ValidateAuthorizationRequest = context => {
            context.Validated();
            return Task.FromResult<object>(null);
        };

        internal static readonly Func<OpenIdConnectValidateTokenRequestContext, Task> ValidateTokenRequest = context => {
            context.Validated();
            return Task.FromResult<object>(null);
        };

        internal static readonly Func<OpenIdConnectGrantAuthorizationCodeContext, Task> GrantAuthorizationCode = context => {
            if (context.Ticket != null && context.Ticket.Identity != null && context.Ticket.Identity.IsAuthenticated) {
                context.Validated();
            }

            return Task.FromResult<object>(null);
        };

        internal static readonly Func<OpenIdConnectGrantRefreshTokenContext, Task> GrantRefreshToken = context => {
            if (context.Ticket != null && context.Ticket.Identity != null && context.Ticket.Identity.IsAuthenticated) {
                context.Validated();
            }

            return Task.FromResult<object>(null);
        };
    }
}
