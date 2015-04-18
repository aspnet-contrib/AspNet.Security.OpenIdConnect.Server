/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.Threading.Tasks;

namespace Owin.Security.OpenIdConnect.Server {
    internal static class DefaultBehavior {
        internal static readonly Func<ValidateAuthorizationRequestNotification, Task> ValidateAuthorizationRequest = context => {
            context.Validated();
            return Task.FromResult<object>(null);
        };

        internal static readonly Func<ValidateTokenRequestNotification, Task> ValidateTokenRequest = context => {
            context.Validated();
            return Task.FromResult<object>(null);
        };

        internal static readonly Func<GrantAuthorizationCodeNotification, Task> GrantAuthorizationCode = context => {
            if (context.Ticket != null && context.Ticket.Identity != null && context.Ticket.Identity.IsAuthenticated) {
                context.Validated();
            }

            return Task.FromResult<object>(null);
        };

        internal static readonly Func<GrantRefreshTokenNotification, Task> GrantRefreshToken = context => {
            if (context.Ticket != null && context.Ticket.Identity != null && context.Ticket.Identity.IsAuthenticated) {
                context.Validated();
            }

            return Task.FromResult<object>(null);
        };
    }
}
