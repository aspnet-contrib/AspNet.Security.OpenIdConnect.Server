/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.Globalization;
using System.IO;
using System.Security.Claims;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Extensions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http.Authentication;
using Microsoft.AspNetCore.Http.Features.Authentication;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace AspNet.Security.OpenIdConnect.Server {
    internal partial class OpenIdConnectServerHandler : AuthenticationHandler<OpenIdConnectServerOptions> {
        private async Task<bool> InvokeAuthorizationEndpointAsync() {
            OpenIdConnectMessage request;

            if (string.Equals(Request.Method, "GET", StringComparison.OrdinalIgnoreCase)) {
                // Create a new authorization request using the
                // parameters retrieved from the query string.
                request = new OpenIdConnectMessage(Request.Query.ToDictionary()) {
                    RequestType = OpenIdConnectRequestType.AuthenticationRequest
                };
            }

            else if (string.Equals(Request.Method, "POST", StringComparison.OrdinalIgnoreCase)) {
                // See http://openid.net/specs/openid-connect-core-1_0.html#FormSerialization
                if (string.IsNullOrEmpty(Request.ContentType)) {
                    Logger.LogInformation("A malformed request has been received by the authorization endpoint.");

                    return await SendErrorPageAsync(new OpenIdConnectMessage {
                        Error = OpenIdConnectConstants.Errors.InvalidRequest,
                        ErrorDescription = "A malformed authorization request has been received: " +
                            "the mandatory 'Content-Type' header was missing from the POST request."
                    });
                }

                // May have media/type; charset=utf-8, allow partial match.
                if (!Request.ContentType.StartsWith("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase)) {
                    Logger.LogInformation("A malformed request has been received by the authorization endpoint.");

                    return await SendErrorPageAsync(new OpenIdConnectMessage {
                        Error = OpenIdConnectConstants.Errors.InvalidRequest,
                        ErrorDescription = "A malformed authorization request has been received: " +
                            "the 'Content-Type' header contained an unexcepted value. " +
                            "Make sure to use 'application/x-www-form-urlencoded'."
                    });
                }

                // Create a new authorization request using the
                // parameters retrieved from the request form.
                var form = await Request.ReadFormAsync(Context.RequestAborted);

                request = new OpenIdConnectMessage(form.ToDictionary()) {
                    RequestType = OpenIdConnectRequestType.AuthenticationRequest
                };
            }

            else {
                Logger.LogInformation("A malformed request has been received by the authorization endpoint.");

                return await SendErrorPageAsync(new OpenIdConnectMessage {
                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = "A malformed authorization request has been received: " +
                                       "make sure to use either GET or POST."
                });
            }

            // Re-assemble the authorization request using the distributed cache if
            // a 'unique_id' parameter has been extracted from the received message.
            var identifier = request.GetRequestId();
            if (!string.IsNullOrEmpty(identifier)) {
                var buffer = await Options.Cache.GetAsync($"asos-request:{identifier}");
                if (buffer == null) {
                    Logger.LogInformation("A unique_id has been provided but no corresponding " +
                                          "OpenID Connect request has been found in the cache.");

                    return await SendErrorPageAsync(new OpenIdConnectMessage {
                        Error = OpenIdConnectConstants.Errors.InvalidRequest,
                        ErrorDescription = "Invalid request: timeout expired."
                    });
                }

                using (var stream = new MemoryStream(buffer))
                using (var reader = new BinaryReader(stream)) {
                    // Make sure the stored authorization request
                    // has been serialized using the same method.
                    var version = reader.ReadInt32();
                    if (version != 1) {
                        await Options.Cache.RemoveAsync($"asos-request:{identifier}");

                        Logger.LogError("An invalid OpenID Connect request has been found in the cache.");

                        return await SendErrorPageAsync(new OpenIdConnectMessage {
                            Error = OpenIdConnectConstants.Errors.InvalidRequest,
                            ErrorDescription = "Invalid request: timeout expired."
                        });
                    }

                    for (int index = 0, length = reader.ReadInt32(); index < length; index++) {
                        var name = reader.ReadString();
                        var value = reader.ReadString();

                        // Skip restoring the parameter retrieved from the stored request
                        // if the OpenID Connect message extracted from the query string
                        // or the request form defined the same parameter.
                        if (!request.Parameters.ContainsKey(name)) {
                            request.SetParameter(name, value);
                        }
                    }
                }
            }

            // Store the authorization request in the ASP.NET context.
            Context.SetOpenIdConnectRequest(request);

            // client_id is mandatory parameter and MUST cause an error when missing.
            // See http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
            if (string.IsNullOrEmpty(request.ClientId)) {
                return await SendErrorPageAsync(new OpenIdConnectMessage {
                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = "client_id was missing"
                });
            }

            // While redirect_uri was not mandatory in OAuth2, this parameter
            // is now declared as REQUIRED and MUST cause an error when missing.
            // See http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
            // To keep AspNet.Security.OpenIdConnect.Server compatible with pure OAuth2 clients,
            // an error is only returned if the request was made by an OpenID Connect client.
            if (string.IsNullOrEmpty(request.RedirectUri) && request.HasScope(OpenIdConnectConstants.Scopes.OpenId)) {
                return await SendErrorPageAsync(new OpenIdConnectMessage {
                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = "redirect_uri must be included when making an OpenID Connect request"
                });
            }

            if (!string.IsNullOrEmpty(request.RedirectUri)) {
                // Note: when specified, redirect_uri MUST be an absolute URI.
                // See http://tools.ietf.org/html/rfc6749#section-3.1.2
                // and http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
                Uri uri;
                if (!Uri.TryCreate(request.RedirectUri, UriKind.Absolute, out uri)) {
                    return await SendErrorPageAsync(new OpenIdConnectMessage {
                        Error = OpenIdConnectConstants.Errors.InvalidRequest,
                        ErrorDescription = "redirect_uri must be absolute"
                    });
                }

                // Note: when specified, redirect_uri MUST NOT include a fragment component.
                // See http://tools.ietf.org/html/rfc6749#section-3.1.2
                // and http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
                else if (!string.IsNullOrEmpty(uri.Fragment)) {
                    return await SendErrorPageAsync(new OpenIdConnectMessage {
                        Error = OpenIdConnectConstants.Errors.InvalidRequest,
                        ErrorDescription = "redirect_uri must not include a fragment"
                    });
                }
            }

            // Reject requests using the unsupported request parameter.
            if (!string.IsNullOrEmpty(request.GetParameter(OpenIdConnectConstants.Parameters.Request))) {
                Logger.LogDebug("The authorization request contained the unsupported request parameter.");

                return await SendErrorPageAsync(new OpenIdConnectMessage {
                    Error = OpenIdConnectConstants.Errors.RequestNotSupported,
                    ErrorDescription = "The request parameter is not supported."
                });
            }

            // Reject requests using the unsupported request_uri parameter.
            else if (!string.IsNullOrEmpty(request.RequestUri)) {
                Logger.LogDebug("The authorization request contained the unsupported request_uri parameter.");

                return await SendErrorPageAsync(new OpenIdConnectMessage {
                    Error = OpenIdConnectConstants.Errors.RequestUriNotSupported,
                    ErrorDescription = "The request_uri parameter is not supported."
                });
            }

            // Reject requests missing the mandatory response_type parameter.
            else if (string.IsNullOrEmpty(request.ResponseType)) {
                Logger.LogDebug("Authorization request missing required response_type parameter");

                return await SendErrorPageAsync(new OpenIdConnectMessage {
                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = "response_type parameter missing"
                });
            }

            // Reject requests whose response_type parameter is unsupported.
            else if (!request.IsNoneFlow() && !request.IsAuthorizationCodeFlow() &&
                     !request.IsImplicitFlow() && !request.IsHybridFlow()) {
                Logger.LogDebug("Authorization request contains unsupported response_type parameter");

                return await SendErrorPageAsync(new OpenIdConnectMessage {
                    Error = OpenIdConnectConstants.Errors.UnsupportedResponseType,
                    ErrorDescription = "response_type unsupported"
                });
            }

            // Reject requests whose response_mode is unsupported.
            else if (!request.IsFormPostResponseMode() && !request.IsFragmentResponseMode() && !request.IsQueryResponseMode()) {
                Logger.LogDebug("Authorization request contains unsupported response_mode parameter");

                return await SendErrorPageAsync(new OpenIdConnectMessage {
                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = "response_mode unsupported"
                });
            }

            // response_mode=query (explicit or not) and a response_type containing id_token
            // or token are not considered as a safe combination and MUST be rejected.
            // See http://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#Security
            else if (request.IsQueryResponseMode() && (request.HasResponseType(OpenIdConnectConstants.ResponseTypes.IdToken) ||
                                                       request.HasResponseType(OpenIdConnectConstants.ResponseTypes.Token))) {
                Logger.LogDebug("Authorization request contains unsafe response_type/response_mode combination");

                return await SendErrorPageAsync(new OpenIdConnectMessage {
                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = "response_type/response_mode combination unsupported"
                });
            }

            // Reject OpenID Connect implicit/hybrid requests missing the mandatory nonce parameter.
            // See http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest,
            // http://openid.net/specs/openid-connect-implicit-1_0.html#RequestParameters
            // and http://openid.net/specs/openid-connect-core-1_0.html#HybridIDToken.
            else if (string.IsNullOrEmpty(request.Nonce) && request.HasScope(OpenIdConnectConstants.Scopes.OpenId) &&
                                                           (request.IsImplicitFlow() || request.IsHybridFlow())) {
                Logger.LogDebug("The 'nonce' parameter was missing");

                return await SendErrorPageAsync(new OpenIdConnectMessage {
                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = "nonce parameter missing"
                });
            }

            // Reject requests containing the id_token response_mode if no openid scope has been received.
            else if (request.HasResponseType(OpenIdConnectConstants.ResponseTypes.IdToken) &&
                    !request.HasScope(OpenIdConnectConstants.Scopes.OpenId)) {
                Logger.LogDebug("The 'openid' scope part was missing");

                return await SendErrorPageAsync(new OpenIdConnectMessage {
                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
                    ErrorDescription = "openid scope missing"
                });
            }

            // Reject requests containing the code response_mode if the token endpoint has been disabled.
            else if (request.HasResponseType(OpenIdConnectConstants.ResponseTypes.Code) && !Options.TokenEndpointPath.HasValue) {
                Logger.LogDebug("Authorization request contains the disabled code response_type");

                return await SendErrorPageAsync(new OpenIdConnectMessage {
                    Error = OpenIdConnectConstants.Errors.UnsupportedResponseType,
                    ErrorDescription = "response_type=code is not supported by this server"
                });
            }

            var validatingContext = new ValidateAuthorizationRequestContext(Context, Options, request);
            await Options.Provider.ValidateAuthorizationRequest(validatingContext);

            if (!validatingContext.IsValidated) {
                Logger.LogError("The authorization request was rejected.");

                return await SendErrorPageAsync(new OpenIdConnectMessage {
                    Error = validatingContext.Error ?? OpenIdConnectConstants.Errors.InvalidClient,
                    ErrorDescription = validatingContext.ErrorDescription,
                    ErrorUri = validatingContext.ErrorUri
                });
            }

            identifier = request.GetRequestId();
            if (string.IsNullOrEmpty(identifier)) {
                // Generate a new 256-bits identifier and associate it with the authorization request.
                identifier = Options.RandomNumberGenerator.GenerateKey(length: 256 / 8);
                request.SetRequestId(identifier);

                using (var stream = new MemoryStream())
                using (var writer = new BinaryWriter(stream)) {
                    writer.Write(/* version: */ 1);
                    writer.Write(request.Parameters.Count);

                    foreach (var parameter in request.Parameters) {
                        writer.Write(parameter.Key);
                        writer.Write(parameter.Value);
                    }

                    // Serialize the authorization request.
                    var bytes = stream.ToArray();

                    // Store the authorization request in the distributed cache.
                    await Options.Cache.SetAsync($"asos-request:{identifier}", bytes, new DistributedCacheEntryOptions {
                        AbsoluteExpiration = Options.SystemClock.UtcNow + TimeSpan.FromHours(1)
                    });
                }
            }

            var notification = new HandleAuthorizationRequestContext(Context, Options, request);
            await Options.Provider.HandleAuthorizationRequest(notification);

            if (notification.HandledResponse) {
                return true;
            }

            return false;
        }

        protected override async Task HandleSignInAsync(SignInContext context) {
            // request may be null when no authorization request has been received
            // or has been already handled by InvokeAuthorizationEndpointAsync.
            var request = Context.GetOpenIdConnectRequest();
            if (request == null) {
                return;
            }

            // Stop processing the request if there's no response grant that matches
            // the authentication type associated with this middleware instance
            // or if the response status code doesn't indicate a successful response.
            if (context == null || Response.StatusCode != 200) {
                return;
            }

            if (Response.HasStarted) {
                Logger.LogCritical(
                    "OpenIdConnectServerHandler.TeardownCoreAsync cannot be called when " +
                    "the response headers have already been sent back to the user agent. " +
                    "Make sure the response body has not been altered and that no middleware " +
                    "has attempted to write to the response stream during this request.");
                return;
            }

            if (!context.Principal.HasClaim(claim => claim.Type == ClaimTypes.NameIdentifier)) {
                Logger.LogError("The returned identity doesn't contain the mandatory ClaimTypes.NameIdentifier claim.");

                await SendNativeErrorPageAsync(new OpenIdConnectMessage {
                    Error = OpenIdConnectConstants.Errors.ServerError,
                    ErrorDescription = "The mandatory ClaimTypes.NameIdentifier claim was not found."
                });

                return;
            }

            // redirect_uri is added to the response message since it's not a mandatory parameter
            // in OAuth 2.0 and can be set or replaced from the ValidateClientRedirectUri event.
            var response = new OpenIdConnectMessage {
                RedirectUri = request.RedirectUri,
                State = request.State
            };

            if (!string.IsNullOrEmpty(request.Nonce)) {
                // Keep the original nonce parameter for later comparison.
                context.Properties[OpenIdConnectConstants.Properties.Nonce] = request.Nonce;
            }

            if (!string.IsNullOrEmpty(request.RedirectUri)) {
                // Keep the original redirect_uri parameter for later comparison.
                context.Properties[OpenIdConnectConstants.Properties.RedirectUri] = request.RedirectUri;
            }

            // Always include the "openid" scope when the developer doesn't explicitly call SetScopes.
            // Note: the application is allowed to specify a different "scopes"
            // parameter when calling AuthenticationManager.SignInAsync: in this case,
            // don't replace the "scopes" property stored in the authentication ticket.
            if (!context.Properties.ContainsKey(OpenIdConnectConstants.Properties.Scopes) &&
                 request.HasScope(OpenIdConnectConstants.Scopes.OpenId)) {
                context.Properties[OpenIdConnectConstants.Properties.Scopes] = OpenIdConnectConstants.Scopes.OpenId;
            }

            string audiences;
            // When a "resources" property cannot be found in the authentication properties, infer it from the "audiences" property.
            if (!context.Properties.ContainsKey(OpenIdConnectConstants.Properties.Resources) &&
                 context.Properties.TryGetValue(OpenIdConnectConstants.Properties.Audiences, out audiences)) {
                context.Properties[OpenIdConnectConstants.Properties.Resources] = audiences;
            }

            // Determine whether an authorization code should be returned
            // and invoke SerializeAuthorizationCodeAsync if necessary.
            if (request.HasResponseType(OpenIdConnectConstants.ResponseTypes.Code)) {
                // Make sure to create a copy of the authentication properties
                // to avoid modifying the properties set on the original ticket.
                var properties = new AuthenticationProperties(context.Properties).Copy();

                // properties.IssuedUtc and properties.ExpiresUtc are always
                // explicitly set to null to avoid aligning the expiration date
                // of the authorization code with the lifetime of the other tokens.
                properties.IssuedUtc = properties.ExpiresUtc = null;

                response.Code = await SerializeAuthorizationCodeAsync(context.Principal, properties, request, response);

                // Ensure that an authorization code is issued to avoid returning an invalid response.
                // See http://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#Combinations
                if (string.IsNullOrEmpty(response.Code)) {
                    Logger.LogError("SerializeAuthorizationCodeAsync returned no authorization code");

                    await SendNativeErrorPageAsync(new OpenIdConnectMessage {
                        Error = OpenIdConnectConstants.Errors.ServerError,
                        ErrorDescription = "no valid authorization code was issued"
                    });

                    return;
                }
            }

            // Determine whether an access token should be returned
            // and invoke SerializeAccessTokenAsync if necessary.
            if (request.HasResponseType(OpenIdConnectConstants.ResponseTypes.Token)) {
                // Make sure to create a copy of the authentication properties
                // to avoid modifying the properties set on the original ticket.
                var properties = new AuthenticationProperties(context.Properties).Copy();

                string resources;
                if (!properties.Items.TryGetValue(OpenIdConnectConstants.Properties.Resources, out resources)) {
                    Logger.LogInformation("No explicit resource has been associated with the authentication ticket: " +
                                          "the access token will thus be issued without any audience attached.");
                }

                // Note: when the "resource" parameter added to the OpenID Connect response
                // is identical to the request parameter, setting it is not necessary.
                if (!string.IsNullOrEmpty(request.Resource) &&
                    !string.Equals(request.Resource, resources, StringComparison.Ordinal)) {
                    response.Resource = resources;
                }

                // Note: when the "scope" parameter added to the OpenID Connect response
                // is identical to the request parameter, setting it is not necessary.
                string scopes;
                properties.Items.TryGetValue(OpenIdConnectConstants.Properties.Scopes, out scopes);
                if (!string.IsNullOrEmpty(request.Scope) &&
                    !string.Equals(request.Scope, scopes, StringComparison.Ordinal)) {
                    response.Scope = scopes;
                }

                response.TokenType = OpenIdConnectConstants.TokenTypes.Bearer;
                response.AccessToken = await SerializeAccessTokenAsync(context.Principal, properties, request, response);

                // Ensure that an access token is issued to avoid returning an invalid response.
                // See http://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#Combinations
                if (string.IsNullOrEmpty(response.AccessToken)) {
                    Logger.LogError("SerializeAccessTokenAsync returned no access token.");

                    await SendNativeErrorPageAsync(new OpenIdConnectMessage {
                        Error = OpenIdConnectConstants.Errors.ServerError,
                        ErrorDescription = "no valid access token was issued"
                    });

                    return;
                }

                // properties.ExpiresUtc is automatically set by SerializeAccessTokenAsync but the end user
                // is free to set a null value directly in the SerializeAccessToken event.
                if (properties.ExpiresUtc.HasValue && properties.ExpiresUtc > Options.SystemClock.UtcNow) {
                    var lifetime = properties.ExpiresUtc.Value - Options.SystemClock.UtcNow;
                    var expiration = (long) (lifetime.TotalSeconds + .5);

                    response.ExpiresIn = expiration.ToString(CultureInfo.InvariantCulture);
                }
            }

            // Determine whether an identity token should be returned
            // and invoke SerializeIdentityTokenAsync if necessary.
            // Note: the identity token MUST be created after the authorization code
            // and the access token to create appropriate at_hash and c_hash claims.
            if (request.HasResponseType(OpenIdConnectConstants.ResponseTypes.IdToken)) {
                // Make sure to create a copy of the authentication properties
                // to avoid modifying the properties set on the original ticket.
                var properties = new AuthenticationProperties(context.Properties).Copy();

                response.IdToken = await SerializeIdentityTokenAsync(context.Principal, properties, request, response);

                // Ensure that an identity token is issued to avoid returning an invalid response.
                // See http://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#Combinations
                if (string.IsNullOrEmpty(response.IdToken)) {
                    Logger.LogError("SerializeIdentityTokenAsync returned no identity token.");

                    await SendNativeErrorPageAsync(new OpenIdConnectMessage {
                        Error = OpenIdConnectConstants.Errors.ServerError,
                        ErrorDescription = "no valid identity token was issued",
                    });

                    return;
                }
            }

            // Remove the OpenID Connect request from the distributed cache.
            var identifier = request.GetRequestId();
            if (!string.IsNullOrEmpty(identifier)) {
                await Options.Cache.RemoveAsync($"asos-request:{identifier}");
            }

            var ticket = new AuthenticationTicket(context.Principal,
                new AuthenticationProperties(context.Properties),
                context.AuthenticationScheme);

            var notification = new ApplyAuthorizationResponseContext(Context, Options, ticket, request, response);
            await Options.Provider.ApplyAuthorizationResponse(notification);

            if (notification.HandledResponse) {
                return;
            }

            else if (notification.Skipped) {
                return;
            }

            await ApplyAuthorizationResponseAsync(request, response);
        }

        protected override async Task<bool> HandleForbiddenAsync(ChallengeContext context) {
            // Stop processing the request if no OpenID Connect
            // message has been found in the current context.
            var request = Context.GetOpenIdConnectRequest();
            if (request == null) {
                return false;
            }

            var response = new OpenIdConnectMessage {
                Error = OpenIdConnectConstants.Errors.AccessDenied,
                ErrorDescription = "The authorization grant has been denied by the resource owner",
                RedirectUri = request.RedirectUri,
                State = request.State
            };

            // Create a new ticket containing an empty identity and
            // the authentication properties extracted from the challenge.
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(),
                new AuthenticationProperties(context.Properties),
                context.AuthenticationScheme);

            var notification = new ApplyAuthorizationResponseContext(Context, Options, ticket, request, response);
            await Options.Provider.ApplyAuthorizationResponse(notification);

            if (notification.HandledResponse) {
                return true;
            }

            else if (notification.Skipped) {
                return false;
            }

            return await SendErrorRedirectAsync(request, response);
        }
    }
}