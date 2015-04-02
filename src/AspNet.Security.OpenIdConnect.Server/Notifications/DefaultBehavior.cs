/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/AspNet-OpenIdConnect-Server/Owin.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.Threading.Tasks;

namespace AspNet.Security.OpenIdConnect.Server {
    internal static class DefaultBehavior {
        internal static readonly Func<OpenIdConnectValidateAuthorizationRequestNotification, Task> ValidateAuthorizationRequest = context => {
            context.Validated();
            return Task.FromResult<object>(null);
        };

        internal static readonly Func<OpenIdConnectValidateTokenRequestNotification, Task> ValidateTokenRequest = context => {
            context.Validated();
            return Task.FromResult<object>(null);
        };

        internal static readonly Func<OpenIdConnectGrantAuthorizationCodeNotification, Task> GrantAuthorizationCode = context => {
            if (context.Ticket != null &&
                context.Ticket.Principal != null &&
                context.Ticket.Principal.Identity != null &&
                context.Ticket.Principal.Identity.IsAuthenticated) {
                context.Validated();
            }

            return Task.FromResult<object>(null);
        };

        internal static readonly Func<OpenIdConnectGrantRefreshTokenNotification, Task> GrantRefreshToken = context => {
            if (context.Ticket != null &&
                context.Ticket.Principal != null &&
                context.Ticket.Principal.Identity != null &&
                context.Ticket.Principal.Identity.IsAuthenticated) {
                context.Validated();
            }

            return Task.FromResult<object>(null);
        };
    }
}
