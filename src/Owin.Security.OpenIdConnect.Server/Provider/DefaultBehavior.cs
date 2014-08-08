// Copyright (c) Microsoft Open Technologies, Inc. All rights reserved. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.Net;
using System.Threading.Tasks;

namespace Owin.Security.OpenIdConnect.Server {
    internal static class DefaultBehavior {
        internal static readonly Func<OpenIdConnectValidateAuthorizeRequestContext, Task> ValidateAuthorizeRequest = context => {
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

        internal static readonly Func<OpenIdConnectSendFormPostMarkupContext, Task> SendFormPostMarkup = async context => {
            context.Response.ContentType = "text/html";

            await context.Response.WriteAsync("<html>\n");
            await context.Response.WriteAsync("<body>\n");
            await context.Response.WriteAsync("<form name='form' method='post' action='" + context.RedirectUri + "'>\n");

            foreach (KeyValuePair<string, string> parameter in context.Payload) {
                var value = WebUtility.HtmlEncode(parameter.Value);
                var key = WebUtility.HtmlEncode(parameter.Key);

                await context.Response.WriteAsync("<input type='hidden' name='" + key + "' value='" + value + "'>\n");
            }

            await context.Response.WriteAsync("<noscript>Click here to finish login: <input type='submit'></noscript>\n");
            await context.Response.WriteAsync("</form>\n");
            await context.Response.WriteAsync("<script>document.form.submit();</script>\n");
            await context.Response.WriteAsync("</body>\n");
            await context.Response.WriteAsync("</html>\n");
        };
    }
}
