/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.Security.Claims;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Extensions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.Net.Http.Headers;
using Newtonsoft.Json.Linq;

namespace AspNet.Security.OpenIdConnect.Server {
    internal partial class OpenIdConnectServerHandler : AuthenticationHandler<OpenIdConnectServerOptions> {
        private async Task<bool> InvokeUserinfoEndpointAsync() {
            OpenIdConnectMessage request;

            if (string.Equals(Request.Method, "GET", StringComparison.OrdinalIgnoreCase)) {
                request = new OpenIdConnectMessage(Request.Query.ToDictionary());
            }

            else if (string.Equals(Request.Method, "POST", StringComparison.OrdinalIgnoreCase)) {
                // See http://openid.net/specs/openid-connect-core-1_0.html#FormSerialization
                if (string.IsNullOrWhiteSpace(Request.ContentType)) {
                    Logger.LogError("The userinfo request was rejected because " +
                                    "the mandatory 'Content-Type' header was missing.");

                    return await SendUserinfoResponseAsync(null, new OpenIdConnectMessage {
                        Error = OpenIdConnectConstants.Errors.InvalidRequest,
                        ErrorDescription = "A malformed userinfo request has been received: " +
                            "the mandatory 'Content-Type' header was missing from the POST request."
                    });
                }

                // May have media/type; charset=utf-8, allow partial match.
                if (!Request.ContentType.StartsWith("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase)) {
                    Logger.LogError("The userinfo request was rejected because an invalid 'Content-Type' " +
                                    "header was received: {ContentType}.", Request.ContentType);

                    return await SendUserinfoResponseAsync(null, new OpenIdConnectMessage {
                        Error = OpenIdConnectConstants.Errors.InvalidRequest,
                        ErrorDescription = "A malformed userinfo request has been received: " +
                            "the 'Content-Type' header contained an unexcepted value. " +
                            "Make sure to use 'application/x-www-form-urlencoded'."
                    });
                }

                var form = await Request.ReadFormAsync(Context.RequestAborted);

                request = new OpenIdConnectMessage(form.ToDictionary());
            }

            else {
                Logger.LogError("The userinfo request was rejected because an invalid " +
                                "HTTP method was received: {Method}.", Request.Method);

                return await SendUserinfoResponseAsync(null, new OpenIdConnectMessage {
                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = "A malformed userinfo request has been received: " +
                                       "make sure to use either GET or POST."
                });
            }

            // Insert the userinfo request in the ASP.NET context.
            Context.SetOpenIdConnectRequest(request);

            string token;
            if (!string.IsNullOrEmpty(request.AccessToken)) {
                token = request.AccessToken;
            }

            else {
                string header = Request.Headers[HeaderNames.Authorization];
                if (string.IsNullOrEmpty(header)) {
                    Logger.LogError("The userinfo request was rejected because " +
                                    "the 'Authorization' header was missing.");

                    return await SendUserinfoResponseAsync(request, new OpenIdConnectMessage {
                        Error = OpenIdConnectConstants.Errors.InvalidRequest,
                        ErrorDescription = "A malformed userinfo request has been received."
                    });
                }

                if (!header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)) {
                    Logger.LogError("The userinfo request was rejected because the " +
                                    "'Authorization' header was invalid: {Header}.", header);

                    return await SendUserinfoResponseAsync(request, new OpenIdConnectMessage {
                        Error = OpenIdConnectConstants.Errors.InvalidRequest,
                        ErrorDescription = "A malformed userinfo request has been received."
                    });
                }

                token = header.Substring("Bearer ".Length);
                if (string.IsNullOrEmpty(token)) {
                    Logger.LogError("The userinfo request was rejected because the access token was missing.");

                    return await SendUserinfoResponseAsync(request, new OpenIdConnectMessage {
                        Error = OpenIdConnectConstants.Errors.InvalidRequest,
                        ErrorDescription = "A malformed userinfo request has been received."
                    });
                }
            }

            var ticket = await DeserializeAccessTokenAsync(token, request);
            if (ticket == null) {
                Logger.LogError("The userinfo request was rejected because access token was invalid.");

                // Note: an invalid token should result in an unauthorized response
                // but returning a 401 status would invoke the previously registered
                // authentication middleware and potentially replace it by a 302 response.
                // To work around this limitation, a 400 error is returned instead.
                // See http://openid.net/specs/openid-connect-core-1_0.html#UserInfoError
                return await SendUserinfoResponseAsync(request, new OpenIdConnectMessage {
                    Error = OpenIdConnectConstants.Errors.InvalidGrant,
                    ErrorDescription = "Invalid token."
                });
            }

            if (!ticket.Properties.ExpiresUtc.HasValue ||
                 ticket.Properties.ExpiresUtc < Options.SystemClock.UtcNow) {
                Logger.LogError("The userinfo request was rejected because access token was expired.");

                // Note: an invalid token should result in an unauthorized response
                // but returning a 401 status would invoke the previously registered
                // authentication middleware and potentially replace it by a 302 response.
                // To work around this limitation, a 400 error is returned instead.
                // See http://openid.net/specs/openid-connect-core-1_0.html#UserInfoError
                return await SendUserinfoResponseAsync(request, new OpenIdConnectMessage {
                    Error = OpenIdConnectConstants.Errors.InvalidGrant,
                    ErrorDescription = "Expired token."
                });
            }

            var context = new ValidateUserinfoRequestContext(Context, Options, request);
            await Options.Provider.ValidateUserinfoRequest(context);

            if (!context.IsValidated) {
                Logger.LogInformation("The userinfo request was rejected by application code.");

                return await SendUserinfoResponseAsync(request, new OpenIdConnectMessage {
                    Error = context.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = context.ErrorDescription,
                    ErrorUri = context.ErrorUri
                });
            }

            var notification = new HandleUserinfoRequestContext(Context, Options, request, ticket);

            notification.Subject = ticket.Principal.GetClaim(ClaimTypes.NameIdentifier);
            notification.Issuer = Context.GetIssuer(Options);

            // Note: when receiving an access token, its audiences list cannot be used for the "aud" claim
            // as the client application is not the intented audience but only an authorized presenter.
            // See http://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse
            foreach (var presenter in ticket.GetPresenters()) {
                notification.Audiences.Add(presenter);
            }

            // The following claims are all optional and should be excluded when
            // no corresponding value has been found in the authentication ticket.
            if (ticket.HasScope(OpenIdConnectConstants.Scopes.Profile)) {
                notification.FamilyName = ticket.Principal.GetClaim(ClaimTypes.Surname);
                notification.GivenName = ticket.Principal.GetClaim(ClaimTypes.GivenName);
                notification.BirthDate = ticket.Principal.GetClaim(ClaimTypes.DateOfBirth);
            }

            if (ticket.HasScope(OpenIdConnectConstants.Scopes.Email)) {
                notification.Email = ticket.Principal.GetClaim(ClaimTypes.Email);
            };

            if (ticket.HasScope(OpenIdConnectConstants.Scopes.Phone)) {
                notification.PhoneNumber = ticket.Principal.GetClaim(ClaimTypes.HomePhone) ??
                                           ticket.Principal.GetClaim(ClaimTypes.MobilePhone) ??
                                           ticket.Principal.GetClaim(ClaimTypes.OtherPhone);
            };

            await Options.Provider.HandleUserinfoRequest(notification);

            if (notification.HandledResponse) {
                return true;
            }

            else if (notification.Skipped) {
                return false;
            }

            // Ensure the "sub" claim has been correctly populated.
            if (string.IsNullOrEmpty(notification.Subject)) {
                Logger.LogError("The mandatory 'sub' claim was missing from the userinfo response.");

                Response.StatusCode = 500;

                return await SendUserinfoResponseAsync(request, new OpenIdConnectMessage {
                    Error = OpenIdConnectConstants.Errors.ServerError,
                    ErrorDescription = "The mandatory 'sub' claim was missing."
                });
            }

            var response = new JObject();

            response.Add(OpenIdConnectConstants.Claims.Subject, notification.Subject);

            if (notification.Address != null) {
                response[OpenIdConnectConstants.Claims.Address] = notification.Address;
            }

            if (!string.IsNullOrEmpty(notification.BirthDate)) {
                response[OpenIdConnectConstants.Claims.Birthdate] = notification.BirthDate;
            }

            if (!string.IsNullOrEmpty(notification.Email)) {
                response[OpenIdConnectConstants.Claims.Email] = notification.Email;
            }

            if (notification.EmailVerified.HasValue) {
                response[OpenIdConnectConstants.Claims.EmailVerified] = notification.EmailVerified.Value;
            }

            if (!string.IsNullOrEmpty(notification.FamilyName)) {
                response[OpenIdConnectConstants.Claims.FamilyName] = notification.FamilyName;
            }

            if (!string.IsNullOrEmpty(notification.GivenName)) {
                response[OpenIdConnectConstants.Claims.GivenName] = notification.GivenName;
            }

            if (!string.IsNullOrEmpty(notification.Issuer)) {
                response[OpenIdConnectConstants.Claims.Issuer] = notification.Issuer;
            }

            if (!string.IsNullOrEmpty(notification.PhoneNumber)) {
                response[OpenIdConnectConstants.Claims.PhoneNumber] = notification.PhoneNumber;
            }

            if (notification.PhoneNumberVerified.HasValue) {
                response[OpenIdConnectConstants.Claims.PhoneNumberVerified] = notification.PhoneNumberVerified.Value;
            }

            if (!string.IsNullOrEmpty(notification.PreferredUsername)) {
                response[OpenIdConnectConstants.Claims.PreferredUsername] = notification.PreferredUsername;
            }

            if (!string.IsNullOrEmpty(notification.Profile)) {
                response[OpenIdConnectConstants.Claims.Profile] = notification.Profile;
            }

            if (!string.IsNullOrEmpty(notification.Website)) {
                response[OpenIdConnectConstants.Claims.Website] = notification.Website;
            }

            switch (notification.Audiences.Count) {
                case 0: break;

                case 1:
                    response.Add(OpenIdConnectConstants.Claims.Audience, notification.Audiences[0]);
                    break;

                default:
                    response.Add(OpenIdConnectConstants.Claims.Audience, JArray.FromObject(notification.Audiences));
                    break;
            }

            foreach (var claim in notification.Claims) {
                // Ignore claims whose value is null.
                if (claim.Value == null) {
                    continue;
                }

                response.Add(claim.Key, claim.Value);
            }

            return await SendUserinfoResponseAsync(request, response);
        }

        private Task<bool> SendUserinfoResponseAsync(OpenIdConnectMessage request, OpenIdConnectMessage response) {
            var payload = new JObject();

            foreach (var parameter in response.Parameters) {
                payload[parameter.Key] = parameter.Value;
            }

            return SendUserinfoResponseAsync(request, payload);
        }

        private async Task<bool> SendUserinfoResponseAsync(OpenIdConnectMessage request, JObject response) {
            if (request == null) {
                request = new OpenIdConnectMessage();
            }

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