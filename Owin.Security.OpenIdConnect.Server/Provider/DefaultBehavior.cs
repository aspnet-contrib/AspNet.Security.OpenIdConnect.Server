// Copyright (c) Microsoft Open Technologies, Inc. All rights reserved. See License.txt in the project root for license information.


using System;
using System.Net;
using System.Threading.Tasks;

namespace Microsoft.Owin.Security.OpenIdConnect.Server {
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

        internal static readonly Func<OpenIdConnectSendFormPostMarkupContext, Task> OnSendFormPostMarkup = async context =>
        {
            var response = context.Response;

            response.ContentType = "text/html";

            await response.WriteAsync("<html>\n");
            await response.WriteAsync("<body>\n");
            await response.WriteAsync("<form name='form' method='post' action='" + context.RedirectUri + "'>\n");

            foreach (var param in context.ReturnParameters)
            {
                var encodedValue = WebUtility.HtmlEncode(param.Value);
                var encodedKey = WebUtility.HtmlEncode(param.Key);
                await response.WriteAsync("<input type='hidden' name='" + encodedKey + "' value='" + encodedValue + "'>\n");
                await response.WriteAsync("<noscript>Click here to finish login: <input type='submit'></noscript>\n");
            }

            await response.WriteAsync("</form>\n");
            await response.WriteAsync("<script>document.form.submit();</script>\n");
            await response.WriteAsync("</body>\n");
            await response.WriteAsync("</html>\n");
        };
    }
}
