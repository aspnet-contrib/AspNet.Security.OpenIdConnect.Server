/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Primitives;
using Microsoft.Extensions.Logging;
using Microsoft.Owin.Security.Infrastructure;
using Newtonsoft.Json.Linq;
using Owin.Security.OpenIdConnect.Extensions;

namespace Owin.Security.OpenIdConnect.Server {
    internal partial class OpenIdConnectServerHandler : AuthenticationHandler<OpenIdConnectServerOptions> {
        private async Task<bool> InvokeUserinfoEndpointAsync() {
            OpenIdConnectRequest request;

            if (string.Equals(Request.Method, "GET", StringComparison.OrdinalIgnoreCase)) {
                request = new OpenIdConnectRequest(Request.Query);
            }

            else if (string.Equals(Request.Method, "POST", StringComparison.OrdinalIgnoreCase)) {
                // See http://openid.net/specs/openid-connect-core-1_0.html#FormSerialization
                if (string.IsNullOrWhiteSpace(Request.ContentType)) {
                    Options.Logger.LogError("The userinfo request was rejected because " +
                                            "the mandatory 'Content-Type' header was missing.");

                    return await SendUserinfoResponseAsync(new OpenIdConnectResponse {
                        Error = OpenIdConnectConstants.Errors.InvalidRequest,
                        ErrorDescription = "A malformed userinfo request has been received: " +
                            "the mandatory 'Content-Type' header was missing from the POST request."
                    });
                }

                // May have media/type; charset=utf-8, allow partial match.
                if (!Request.ContentType.StartsWith("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase)) {
                    Options.Logger.LogError("The userinfo request was rejected because an invalid 'Content-Type' " +
                                            "header was received: {ContentType}.", Request.ContentType);

                    return await SendUserinfoResponseAsync(new OpenIdConnectResponse {
                        Error = OpenIdConnectConstants.Errors.InvalidRequest,
                        ErrorDescription = "A malformed userinfo request has been received: " +
                            "the 'Content-Type' header contained an unexcepted value. " +
                            "Make sure to use 'application/x-www-form-urlencoded'."
                    });
                }

                request = new OpenIdConnectRequest(await Request.ReadFormAsync());
            }

            else {
                Options.Logger.LogError("The userinfo request was rejected because an invalid " +
                                        "HTTP method was received: {Method}.", Request.Method);

                return await SendUserinfoResponseAsync(new OpenIdConnectResponse {
                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = "A malformed userinfo request has been received: " +
                                       "make sure to use either GET or POST."
                });
            }

            // Note: set the message type before invoking the ExtractUserinfoRequest event.
            request.SetProperty(OpenIdConnectConstants.Properties.MessageType,
                                OpenIdConnectConstants.MessageTypes.Userinfo);

            // Insert the userinfo request in the OWIN context.
            Context.SetOpenIdConnectRequest(request);

            var @event = new ExtractUserinfoRequestContext(Context, Options, request);
            await Options.Provider.ExtractUserinfoRequest(@event);

            if (@event.HandledResponse) {
                return true;
            }

            else if (@event.Skipped) {
                return false;
            }

            else if (@event.IsRejected) {
                Options.Logger.LogError("The userinfo request was rejected with the following error: {Error} ; {Description}",
                                        /* Error: */ @event.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
                                        /* Description: */ @event.ErrorDescription);

                return await SendUserinfoResponseAsync(new OpenIdConnectResponse {
                    Error = @event.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = @event.ErrorDescription,
                    ErrorUri = @event.ErrorUri
                });
            }

            string token;
            if (!string.IsNullOrEmpty(request.AccessToken)) {
                token = request.AccessToken;
            }

            else {
                var header = Request.Headers.Get("Authorization");
                if (string.IsNullOrEmpty(header)) {
                    Options.Logger.LogError("The userinfo request was rejected because " +
                                            "the 'Authorization' header was missing.");

                    return await SendUserinfoResponseAsync(new OpenIdConnectResponse {
                        Error = OpenIdConnectConstants.Errors.InvalidRequest,
                        ErrorDescription = "A malformed userinfo request has been received."
                    });
                }

                if (!header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)) {
                    Options.Logger.LogError("The userinfo request was rejected because the " +
                                            "'Authorization' header was invalid: {Header}.", header);

                    return await SendUserinfoResponseAsync(new OpenIdConnectResponse {
                        Error = OpenIdConnectConstants.Errors.InvalidRequest,
                        ErrorDescription = "A malformed userinfo request has been received."
                    });
                }

                token = header.Substring("Bearer ".Length);
                if (string.IsNullOrEmpty(token)) {
                    Options.Logger.LogError("The userinfo request was rejected because the access token was missing.");

                    return await SendUserinfoResponseAsync(new OpenIdConnectResponse {
                        Error = OpenIdConnectConstants.Errors.InvalidRequest,
                        ErrorDescription = "A malformed userinfo request has been received."
                    });
                }
            }

            var context = new ValidateUserinfoRequestContext(Context, Options, request);
            await Options.Provider.ValidateUserinfoRequest(context);

            if (context.HandledResponse) {
                return true;
            }

            else if (context.Skipped) {
                return false;
            }

            else if (!context.IsValidated) {
                Options.Logger.LogError("The userinfo request was rejected with the following error: {Error} ; {Description}",
                                        /* Error: */ context.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
                                        /* Description: */ context.ErrorDescription);

                return await SendUserinfoResponseAsync(new OpenIdConnectResponse {
                    Error = context.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = context.ErrorDescription,
                    ErrorUri = context.ErrorUri
                });
            }

            var ticket = await DeserializeAccessTokenAsync(token, request);
            if (ticket == null) {
                Options.Logger.LogError("The userinfo request was rejected because the access token was invalid.");

                // Note: an invalid token should result in an unauthorized response
                // but returning a 401 status would invoke the previously registered
                // authentication middleware and potentially replace it by a 302 response.
                // To work around this limitation, a 400 error is returned instead.
                // See http://openid.net/specs/openid-connect-core-1_0.html#UserInfoError
                return await SendUserinfoResponseAsync(new OpenIdConnectResponse {
                    Error = OpenIdConnectConstants.Errors.InvalidGrant,
                    ErrorDescription = "Invalid token."
                });
            }

            if (ticket.Properties.ExpiresUtc.HasValue &&
                ticket.Properties.ExpiresUtc < Options.SystemClock.UtcNow) {
                Options.Logger.LogError("The userinfo request was rejected because the access token was expired.");

                // Note: an invalid token should result in an unauthorized response
                // but returning a 401 status would invoke the previously registered
                // authentication middleware and potentially replace it by a 302 response.
                // To work around this limitation, a 400 error is returned instead.
                // See http://openid.net/specs/openid-connect-core-1_0.html#UserInfoError
                return await SendUserinfoResponseAsync(new OpenIdConnectResponse {
                    Error = OpenIdConnectConstants.Errors.InvalidGrant,
                    ErrorDescription = "Expired token."
                });
            }

            var notification = new HandleUserinfoRequestContext(Context, Options, request, ticket);
            notification.Issuer = Context.GetIssuer(Options);

            // Try to resolve the subject using one of the well-known sub/name identifier/upn claims.
            notification.Subject = ticket.Identity.GetClaim(OpenIdConnectConstants.Claims.Subject) ??
                                   ticket.Identity.GetClaim(ClaimTypes.NameIdentifier) ??
                                   ticket.Identity.GetClaim(ClaimTypes.Upn);

            // Note: when receiving an access token, its audiences list cannot be used for the "aud" claim
            // as the client application is not the intented audience but only an authorized presenter.
            // See http://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse
            foreach (var presenter in ticket.GetPresenters()) {
                notification.Audiences.Add(presenter);
            }

            // The following claims are all optional and should be excluded when
            // no corresponding value has been found in the authentication ticket.
            if (ticket.HasScope(OpenIdConnectConstants.Scopes.Profile)) {
                notification.FamilyName = ticket.Identity.GetClaim(OpenIdConnectConstants.Claims.FamilyName) ??
                                          ticket.Identity.GetClaim(ClaimTypes.Surname);

                notification.GivenName = ticket.Identity.GetClaim(OpenIdConnectConstants.Claims.GivenName) ??
                                         ticket.Identity.GetClaim(ClaimTypes.GivenName);

                notification.BirthDate = ticket.Identity.GetClaim(OpenIdConnectConstants.Claims.Birthdate) ??
                                         ticket.Identity.GetClaim(ClaimTypes.DateOfBirth);
            }

            if (ticket.HasScope(OpenIdConnectConstants.Scopes.Email)) {
                notification.Email = ticket.Identity.GetClaim(OpenIdConnectConstants.Claims.Email) ??
                                     ticket.Identity.GetClaim(ClaimTypes.Email);
            }

            if (ticket.HasScope(OpenIdConnectConstants.Scopes.Phone)) {
                notification.PhoneNumber = ticket.Identity.GetClaim(OpenIdConnectConstants.Claims.PhoneNumber) ??
                                           ticket.Identity.GetClaim(ClaimTypes.HomePhone) ??
                                           ticket.Identity.GetClaim(ClaimTypes.MobilePhone) ??
                                           ticket.Identity.GetClaim(ClaimTypes.OtherPhone);
            }

            await Options.Provider.HandleUserinfoRequest(notification);

            if (notification.HandledResponse) {
                return true;
            }

            else if (notification.Skipped) {
                return false;
            }

            else if (notification.IsRejected) {
                Options.Logger.LogError("The userinfo request was rejected with the following error: {Error} ; {Description}",
                                        /* Error: */ notification.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
                                        /* Description: */ notification.ErrorDescription);

                return await SendUserinfoResponseAsync(new OpenIdConnectResponse {
                    Error = notification.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = notification.ErrorDescription,
                    ErrorUri = notification.ErrorUri
                });
            }

            // Ensure the "sub" claim has been correctly populated.
            if (string.IsNullOrEmpty(notification.Subject)) {
                Options.Logger.LogError("The mandatory 'sub' claim was missing from the userinfo response.");

                Response.StatusCode = 500;

                return await SendUserinfoResponseAsync(new OpenIdConnectResponse {
                    Error = OpenIdConnectConstants.Errors.ServerError,
                    ErrorDescription = "The mandatory 'sub' claim was missing."
                });
            }

            var response = new OpenIdConnectResponse {
                [OpenIdConnectConstants.Claims.Subject] = notification.Subject,
                [OpenIdConnectConstants.Claims.Address] = notification.Address,
                [OpenIdConnectConstants.Claims.Birthdate] = notification.BirthDate,
                [OpenIdConnectConstants.Claims.Email] = notification.Email,
                [OpenIdConnectConstants.Claims.EmailVerified] = notification.EmailVerified,
                [OpenIdConnectConstants.Claims.FamilyName] = notification.FamilyName,
                [OpenIdConnectConstants.Claims.GivenName] = notification.GivenName,
                [OpenIdConnectConstants.Claims.Issuer] = notification.Issuer,
                [OpenIdConnectConstants.Claims.PhoneNumber] = notification.PhoneNumber,
                [OpenIdConnectConstants.Claims.PhoneNumberVerified] = notification.PhoneNumberVerified,
                [OpenIdConnectConstants.Claims.PreferredUsername] = notification.PreferredUsername,
                [OpenIdConnectConstants.Claims.Profile] = notification.Profile,
                [OpenIdConnectConstants.Claims.Website] = notification.Website
            };

            switch (notification.Audiences.Count) {
                case 0: break;

                case 1:
                    response[OpenIdConnectConstants.Claims.Audience] = notification.Audiences.ElementAt(0);
                    break;

                default:
                    response[OpenIdConnectConstants.Claims.Audience] = new JArray(notification.Audiences);
                    break;
            }

            foreach (var claim in notification.Claims) {
                // Ignore claims whose value is null.
                if (claim.Value == null) {
                    continue;
                }

                response.SetParameter(claim.Key, claim.Value);
            }

            return await SendUserinfoResponseAsync(response);
        }

        private async Task<bool> SendUserinfoResponseAsync(OpenIdConnectResponse response) {
            var request = Context.GetOpenIdConnectRequest();
            Context.SetOpenIdConnectResponse(response);

            var notification = new ApplyUserinfoResponseContext(Context, Options, request, response);
            await Options.Provider.ApplyUserinfoResponse(notification);

            if (notification.HandledResponse) {
                return true;
            }

            else if (notification.Skipped) {
                return false;
            }

            return await SendPayloadAsync(response);
        }
    }
}
