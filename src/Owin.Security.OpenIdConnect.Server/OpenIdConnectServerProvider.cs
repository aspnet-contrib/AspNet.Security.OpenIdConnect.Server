/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.Threading.Tasks;

namespace Owin.Security.OpenIdConnect.Server
{
    /// <summary>
    /// Defines a provider exposing events used by the OpenID Connect server to communicate
    /// with the web application while processing incoming requests. This class can be used
    /// as a virtual base class, but it also offers delegate properties that can be used to
    /// handle individual calls without having to explicitly declare a new subclassed type.
    /// </summary>
    public class OpenIdConnectServerProvider
    {
        /// <summary>
        /// Represents an event called for each HTTP request to determine if
        /// it should be handled by the OpenID Connect server middleware.
        /// </summary>
        public Func<MatchEndpointContext, Task> OnMatchEndpoint { get; set; }
            = context => Task.CompletedTask;

        /// <summary>
        /// Represents an event called for each request to the authorization endpoint to give the user code
        /// a chance to manually extract the authorization request from the ambient HTTP context.
        /// </summary>
        public Func<ExtractAuthorizationRequestContext, Task> OnExtractAuthorizationRequest { get; set; }
            = context => Task.CompletedTask;

        /// <summary>
        /// Represents an event called for each request to the configuration endpoint to give the user code
        /// a chance to manually extract the configuration request from the ambient HTTP context.
        /// </summary>
        public Func<ExtractConfigurationRequestContext, Task> OnExtractConfigurationRequest { get; set; }
            = context => Task.CompletedTask;

        /// <summary>
        /// Represents an event called for each request to the cryptography endpoint to give the user code
        /// a chance to manually extract the configuration request from the ambient HTTP context.
        /// </summary>
        public Func<ExtractCryptographyRequestContext, Task> OnExtractCryptographyRequest { get; set; }
            = context => Task.CompletedTask;

        /// <summary>
        /// Represents an event called for each request to the introspection endpoint to give the user code
        /// a chance to manually extract the configuration request from the ambient HTTP context.
        /// </summary>
        public Func<ExtractIntrospectionRequestContext, Task> OnExtractIntrospectionRequest { get; set; }
            = context => Task.CompletedTask;

        /// <summary>
        /// Represents an event called for each request to the logout endpoint to give the user code
        /// a chance to manually extract the configuration request from the ambient HTTP context.
        /// </summary>
        public Func<ExtractLogoutRequestContext, Task> OnExtractLogoutRequest { get; set; }
            = context => Task.CompletedTask;

        /// <summary>
        /// Represents an event called for each request to the revocation endpoint to give the user code
        /// a chance to manually extract the configuration request from the ambient HTTP context.
        /// </summary>
        public Func<ExtractRevocationRequestContext, Task> OnExtractRevocationRequest { get; set; }
            = context => Task.CompletedTask;

        /// <summary>
        /// Represents an event called for each request to the token endpoint to give the user code
        /// a chance to manually extract the configuration request from the ambient HTTP context.
        /// </summary>
        public Func<ExtractTokenRequestContext, Task> OnExtractTokenRequest { get; set; }
            = context => Task.CompletedTask;

        /// <summary>
        /// Represents an event called for each request to the userinfo endpoint to give the user code
        /// a chance to manually extract the configuration request from the ambient HTTP context.
        /// </summary>
        public Func<ExtractUserinfoRequestContext, Task> OnExtractUserinfoRequest { get; set; }
            = context => Task.CompletedTask;

        /// <summary>
        /// Represents an event called for each request to the authorization endpoint
        /// to determine if the request is valid and should continue to be processed.
        /// </summary>
        public Func<ValidateAuthorizationRequestContext, Task> OnValidateAuthorizationRequest { get; set; }
            = context => Task.CompletedTask;

        /// <summary>
        /// Represents an event called for each request to the configuration endpoint
        /// to determine if the request is valid and should continue to be processed.
        /// </summary>
        public Func<ValidateConfigurationRequestContext, Task> OnValidateConfigurationRequest { get; set; }
            = context => Task.CompletedTask;

        /// <summary>
        /// Represents an event called for each request to the cryptography endpoint
        /// to determine if the request is valid and should continue to be processed.
        /// </summary>
        public Func<ValidateCryptographyRequestContext, Task> OnValidateCryptographyRequest { get; set; }
            = context => Task.CompletedTask;

        /// <summary>
        /// Represents an event called for each request to the introspection endpoint
        /// to determine if the request is valid and should continue to be processed.
        /// </summary>
        public Func<ValidateIntrospectionRequestContext, Task> OnValidateIntrospectionRequest { get; set; }
            = context => Task.CompletedTask;

        /// <summary>
        /// Represents an event called for each request to the logout endpoint
        /// to determine if the request is valid and should continue to be processed.
        /// </summary>
        public Func<ValidateLogoutRequestContext, Task> OnValidateLogoutRequest { get; set; }
            = context => Task.CompletedTask;

        /// <summary>
        /// Represents an event called for each request to the revocation endpoint
        /// to determine if the request is valid and should continue to be processed.
        /// </summary>
        public Func<ValidateRevocationRequestContext, Task> OnValidateRevocationRequest { get; set; }
            = context => Task.CompletedTask;

        /// <summary>
        /// Represents an event called for each request to the token endpoint
        /// to determine if the request is valid and should continue to be processed.
        /// </summary>
        public Func<ValidateTokenRequestContext, Task> OnValidateTokenRequest { get; set; }
            = context => Task.CompletedTask;

        /// <summary>
        /// Represents an event called for each request to the userinfo endpoint
        /// to determine if the request is valid and should continue to be processed.
        /// </summary>
        public Func<ValidateUserinfoRequestContext, Task> OnValidateUserinfoRequest { get; set; }
            = context => Task.CompletedTask;

        /// <summary>
        /// Represents an event called for each validated authorization request
        /// to allow the user code to decide how the request should be handled.
        /// </summary>
        public Func<HandleAuthorizationRequestContext, Task> OnHandleAuthorizationRequest { get; set; }
            = context => Task.CompletedTask;

        /// <summary>
        /// Represents an event called for each validated configuration request
        /// to allow the user code to decide how the request should be handled.
        /// </summary>
        public Func<HandleConfigurationRequestContext, Task> OnHandleConfigurationRequest { get; set; }
            = context => Task.CompletedTask;

        /// <summary>
        /// Represents an event called for each validated cryptography request
        /// to allow the user code to decide how the request should be handled.
        /// </summary>
        public Func<HandleCryptographyRequestContext, Task> OnHandleCryptographyRequest { get; set; }
            = context => Task.CompletedTask;

        /// <summary>
        /// Represents an event called for each validated introspection request
        /// to allow the user code to decide how the request should be handled.
        /// </summary>
        public Func<HandleIntrospectionRequestContext, Task> OnHandleIntrospectionRequest { get; set; }
            = context => Task.CompletedTask;

        /// <summary>
        /// Represents an event called for each validated logout request
        /// to allow the user code to decide how the request should be handled.
        /// </summary>
        public Func<HandleLogoutRequestContext, Task> OnHandleLogoutRequest { get; set; }
            = context => Task.CompletedTask;

        /// <summary>
        /// Represents an event called for each validated revocation request
        /// to allow the user code to decide how the request should be handled.
        /// </summary>
        public Func<HandleRevocationRequestContext, Task> OnHandleRevocationRequest { get; set; }
            = context => Task.CompletedTask;

        /// <summary>
        /// Represents an event called for each validated token request
        /// to allow the user code to decide how the request should be handled.
        /// </summary>
        public Func<HandleTokenRequestContext, Task> OnHandleTokenRequest { get; set; }
            = context => Task.CompletedTask;

        /// <summary>
        /// Represents an event called for each validated userinfo request
        /// to allow the user code to decide how the request should be handled.
        /// </summary>
        public Func<HandleUserinfoRequestContext, Task> OnHandleUserinfoRequest { get; set; }
            = context => Task.CompletedTask;

        /// <summary>
        /// Represents an event called when processing a challenge response.
        /// </summary>
        public Func<ProcessChallengeResponseContext, Task> OnProcessChallengeResponse { get; set; }
            = context => Task.CompletedTask;

        /// <summary>
        /// Represents an event called when processing a sign-in response.
        /// </summary>
        public Func<ProcessSigninResponseContext, Task> OnProcessSigninResponse { get; set; }
            = context => Task.CompletedTask;

        /// <summary>
        /// Represents an event called when processing a sign-out response.
        /// </summary>
        public Func<ProcessSignoutResponseContext, Task> OnProcessSignoutResponse { get; set; }
            = context => Task.CompletedTask;

        /// <summary>
        /// Represents an event called before the authorization response is returned to the caller.
        /// </summary>
        public Func<ApplyAuthorizationResponseContext, Task> OnApplyAuthorizationResponse { get; set; }
            = context => Task.CompletedTask;

        /// <summary>
        /// Represents an event called before the configuration response is returned to the caller.
        /// </summary>
        public Func<ApplyConfigurationResponseContext, Task> OnApplyConfigurationResponse { get; set; }
            = context => Task.CompletedTask;

        /// <summary>
        /// Represents an event called before the cryptography response is returned to the caller.
        /// </summary>
        public Func<ApplyCryptographyResponseContext, Task> OnApplyCryptographyResponse { get; set; }
            = context => Task.CompletedTask;

        /// <summary>
        /// Represents an event called before the introspection response is returned to the caller.
        /// </summary>
        public Func<ApplyIntrospectionResponseContext, Task> OnApplyIntrospectionResponse { get; set; }
            = context => Task.CompletedTask;

        /// <summary>
        /// Represents an event called before the logout response is returned to the caller.
        /// </summary>
        public Func<ApplyLogoutResponseContext, Task> OnApplyLogoutResponse { get; set; }
            = context => Task.CompletedTask;

        /// <summary>
        /// Represents an event called before the revocation response is returned to the caller.
        /// </summary>
        public Func<ApplyRevocationResponseContext, Task> OnApplyRevocationResponse { get; set; }
            = context => Task.CompletedTask;

        /// <summary>
        /// Represents an event called before the token response is returned to the caller.
        /// </summary>
        public Func<ApplyTokenResponseContext, Task> OnApplyTokenResponse { get; set; }
            = context => Task.CompletedTask;

        /// <summary>
        /// Represents an event called before the userinfo response is returned to the caller.
        /// </summary>
        public Func<ApplyUserinfoResponseContext, Task> OnApplyUserinfoResponse { get; set; }
            = context => Task.CompletedTask;

        /// <summary>
        /// Represents an event called when serializing an authorization code.
        /// </summary>
        public Func<SerializeAuthorizationCodeContext, Task> OnSerializeAuthorizationCode { get; set; }
            = context => Task.CompletedTask;

        /// <summary>
        /// Represents an event called when serializing an access token.
        /// </summary>
        public Func<SerializeAccessTokenContext, Task> OnSerializeAccessToken { get; set; }
            = context => Task.CompletedTask;

        /// <summary>
        /// Represents an event called when serializing an identity token.
        /// </summary>
        public Func<SerializeIdentityTokenContext, Task> OnSerializeIdentityToken { get; set; }
            = context => Task.CompletedTask;

        /// <summary>
        /// Represents an event called when serializing a refresh token.
        /// </summary>
        public Func<SerializeRefreshTokenContext, Task> OnSerializeRefreshToken { get; set; }
            = context => Task.CompletedTask;

        /// <summary>
        /// Represents an event called when deserializing an authorization code.
        /// </summary>
        public Func<DeserializeAuthorizationCodeContext, Task> OnDeserializeAuthorizationCode { get; set; }
            = context => Task.CompletedTask;

        /// <summary>
        /// Represents an event called when deserializing an access token.
        /// </summary>
        public Func<DeserializeAccessTokenContext, Task> OnDeserializeAccessToken { get; set; }
            = context => Task.CompletedTask;

        /// <summary>
        /// Represents an event called when deserializing an identity token.
        /// </summary>
        public Func<DeserializeIdentityTokenContext, Task> OnDeserializeIdentityToken { get; set; }
            = context => Task.CompletedTask;

        /// <summary>
        /// Represents an event called when deserializing a refresh token.
        /// </summary>
        public Func<DeserializeRefreshTokenContext, Task> OnDeserializeRefreshToken { get; set; }
            = context => Task.CompletedTask;

        /// <summary>
        /// Represents an event called for each HTTP request to determine if
        /// it should be handled by the OpenID Connect server middleware.
        /// </summary>
        /// <param name="context">The context instance associated with this event.</param>
        /// <returns>A <see cref="Task"/> that can be used to monitor the asynchronous operation.</returns>
        public virtual Task MatchEndpoint(MatchEndpointContext context)
            => OnMatchEndpoint(context);

        /// <summary>
        /// Represents an event called for each request to the authorization endpoint to give the user code
        /// a chance to manually extract the authorization request from the ambient HTTP context.
        /// </summary>
        /// <param name="context">The context instance associated with this event.</param>
        /// <returns>A <see cref="Task"/> that can be used to monitor the asynchronous operation.</returns>
        public virtual Task ExtractAuthorizationRequest(ExtractAuthorizationRequestContext context)
            => OnExtractAuthorizationRequest(context);

        /// <summary>
        /// Represents an event called for each request to the configuration endpoint to give the user code
        /// a chance to manually extract the configuration request from the ambient HTTP context.
        /// </summary>
        /// <param name="context">The context instance associated with this event.</param>
        /// <returns>A <see cref="Task"/> that can be used to monitor the asynchronous operation.</returns>
        public virtual Task ExtractConfigurationRequest(ExtractConfigurationRequestContext context)
            => OnExtractConfigurationRequest(context);

        /// <summary>
        /// Represents an event called for each request to the cryptography endpoint to give the user code
        /// a chance to manually extract the cryptography request from the ambient HTTP context.
        /// </summary>
        /// <param name="context">The context instance associated with this event.</param>
        /// <returns>A <see cref="Task"/> that can be used to monitor the asynchronous operation.</returns>
        public virtual Task ExtractCryptographyRequest(ExtractCryptographyRequestContext context)
            => OnExtractCryptographyRequest(context);

        /// <summary>
        /// Represents an event called for each request to the introspection endpoint to give the user code
        /// a chance to manually extract the introspection request from the ambient HTTP context.
        /// </summary>
        /// <param name="context">The context instance associated with this event.</param>
        /// <returns>A <see cref="Task"/> that can be used to monitor the asynchronous operation.</returns>
        public virtual Task ExtractIntrospectionRequest(ExtractIntrospectionRequestContext context)
            => OnExtractIntrospectionRequest(context);

        /// <summary>
        /// Represents an event called for each request to the logout endpoint to give the user code
        /// a chance to manually extract the logout request from the ambient HTTP context.
        /// </summary>
        /// <param name="context">The context instance associated with this event.</param>
        /// <returns>A <see cref="Task"/> that can be used to monitor the asynchronous operation.</returns>
        public virtual Task ExtractLogoutRequest(ExtractLogoutRequestContext context)
            => OnExtractLogoutRequest(context);

        /// <summary>
        /// Represents an event called for each request to the revocation endpoint to give the user code
        /// a chance to manually extract the revocation request from the ambient HTTP context.
        /// </summary>
        /// <param name="context">The context instance associated with this event.</param>
        /// <returns>A <see cref="Task"/> that can be used to monitor the asynchronous operation.</returns>
        public virtual Task ExtractRevocationRequest(ExtractRevocationRequestContext context)
            => OnExtractRevocationRequest(context);

        /// <summary>
        /// Represents an event called for each request to the token endpoint to give the user code
        /// a chance to manually extract the token request from the ambient HTTP context.
        /// </summary>
        /// <param name="context">The context instance associated with this event.</param>
        /// <returns>A <see cref="Task"/> that can be used to monitor the asynchronous operation.</returns>
        public virtual Task ExtractTokenRequest(ExtractTokenRequestContext context)
            => OnExtractTokenRequest(context);

        /// <summary>
        /// Represents an event called for each request to the userinfo endpoint to give the user code
        /// a chance to manually extract the userinfo request from the ambient HTTP context.
        /// </summary>
        /// <param name="context">The context instance associated with this event.</param>
        /// <returns>A <see cref="Task"/> that can be used to monitor the asynchronous operation.</returns>
        public virtual Task ExtractUserinfoRequest(ExtractUserinfoRequestContext context)
            => OnExtractUserinfoRequest(context);

        /// <summary>
        /// Represents an event called for each request to the authorization endpoint
        /// to determine if the request is valid and should continue.
        /// </summary>
        /// <param name="context">The context instance associated with this event.</param>
        /// <returns>A <see cref="Task"/> that can be used to monitor the asynchronous operation.</returns>
        public virtual Task ValidateAuthorizationRequest(ValidateAuthorizationRequestContext context)
            => OnValidateAuthorizationRequest(context);

        /// <summary>
        /// Represents an event called for each request to the configuration endpoint
        /// to determine if the request is valid and should continue.
        /// </summary>
        /// <param name="context">The context instance associated with this event.</param>
        /// <returns>A <see cref="Task"/> that can be used to monitor the asynchronous operation.</returns>
        public virtual Task ValidateConfigurationRequest(ValidateConfigurationRequestContext context)
            => OnValidateConfigurationRequest(context);

        /// <summary>
        /// Represents an event called for each request to the cryptography endpoint
        /// to determine if the request is valid and should continue.
        /// </summary>
        /// <param name="context">The context instance associated with this event.</param>
        /// <returns>A <see cref="Task"/> that can be used to monitor the asynchronous operation.</returns>
        public virtual Task ValidateCryptographyRequest(ValidateCryptographyRequestContext context)
            => OnValidateCryptographyRequest(context);

        /// <summary>
        /// Represents an event called for each request to the introspection endpoint
        /// to determine if the request is valid and should continue.
        /// </summary>
        /// <param name="context">The context instance associated with this event.</param>
        /// <returns>A <see cref="Task"/> that can be used to monitor the asynchronous operation.</returns>
        public virtual Task ValidateIntrospectionRequest(ValidateIntrospectionRequestContext context)
            => OnValidateIntrospectionRequest(context);

        /// <summary>
        /// Represents an event called for each request to the logout endpoint
        /// to determine if the request is valid and should continue.
        /// </summary>
        /// <param name="context">The context instance associated with this event.</param>
        /// <returns>A <see cref="Task"/> that can be used to monitor the asynchronous operation.</returns>
        public virtual Task ValidateLogoutRequest(ValidateLogoutRequestContext context)
            => OnValidateLogoutRequest(context);

        /// <summary>
        /// Represents an event called for each request to the revocation endpoint
        /// to determine if the request is valid and should continue.
        /// </summary>
        /// <param name="context">The context instance associated with this event.</param>
        /// <returns>A <see cref="Task"/> that can be used to monitor the asynchronous operation.</returns>
        public virtual Task ValidateRevocationRequest(ValidateRevocationRequestContext context)
            => OnValidateRevocationRequest(context);

        /// <summary>
        /// Represents an event called for each request to the token endpoint
        /// to determine if the request is valid and should continue.
        /// </summary>
        /// <param name="context">The context instance associated with this event.</param>
        /// <returns>A <see cref="Task"/> that can be used to monitor the asynchronous operation.</returns>
        public virtual Task ValidateTokenRequest(ValidateTokenRequestContext context)
            => OnValidateTokenRequest(context);

        /// <summary>
        /// Represents an event called for each request to the userinfo endpoint
        /// to determine if the request is valid and should continue.
        /// </summary>
        /// <param name="context">The context instance associated with this event.</param>
        /// <returns>A <see cref="Task"/> that can be used to monitor the asynchronous operation.</returns>
        public virtual Task ValidateUserinfoRequest(ValidateUserinfoRequestContext context)
            => OnValidateUserinfoRequest(context);

        /// <summary>
        /// Represents an event called for each validated authorization request
        /// to allow the user code to decide how the request should be handled.
        /// </summary>
        /// <param name="context">The context instance associated with this event.</param>
        /// <returns>A <see cref="Task"/> that can be used to monitor the asynchronous operation.</returns>
        public virtual Task HandleAuthorizationRequest(HandleAuthorizationRequestContext context)
            => OnHandleAuthorizationRequest(context);

        /// <summary>
        /// Represents an event called for each validated configuration request
        /// to allow the user code to decide how the request should be handled.
        /// </summary>
        /// <param name="context">The context instance associated with this event.</param>
        /// <returns>A <see cref="Task"/> that can be used to monitor the asynchronous operation.</returns>
        public virtual Task HandleConfigurationRequest(HandleConfigurationRequestContext context)
            => OnHandleConfigurationRequest(context);

        /// <summary>
        /// Represents an event called for each validated cryptography request
        /// to allow the user code to decide how the request should be handled.
        /// </summary>
        /// <param name="context">The context instance associated with this event.</param>
        /// <returns>A <see cref="Task"/> that can be used to monitor the asynchronous operation.</returns>
        public virtual Task HandleCryptographyRequest(HandleCryptographyRequestContext context)
            => OnHandleCryptographyRequest(context);

        /// <summary>
        /// Represents an event called for each validated introspection request
        /// to allow the user code to decide how the request should be handled.
        /// </summary>
        /// <param name="context">The context instance associated with this event.</param>
        /// <returns>A <see cref="Task"/> that can be used to monitor the asynchronous operation.</returns>
        public virtual Task HandleIntrospectionRequest(HandleIntrospectionRequestContext context)
            => OnHandleIntrospectionRequest(context);

        /// <summary>
        /// Represents an event called for each validated logout request
        /// to allow the user code to decide how the request should be handled.
        /// </summary>
        /// <param name="context">The context instance associated with this event.</param>
        /// <returns>A <see cref="Task"/> that can be used to monitor the asynchronous operation.</returns>
        public virtual Task HandleLogoutRequest(HandleLogoutRequestContext context)
            => OnHandleLogoutRequest(context);

        /// <summary>
        /// Represents an event called for each validated revocation request
        /// to allow the user code to decide how the request should be handled.
        /// </summary>
        /// <param name="context">The context instance associated with this event.</param>
        /// <returns>A <see cref="Task"/> that can be used to monitor the asynchronous operation.</returns>
        public virtual Task HandleRevocationRequest(HandleRevocationRequestContext context)
            => OnHandleRevocationRequest(context);

        /// <summary>
        /// Represents an event called for each validated token request
        /// to allow the user code to decide how the request should be handled.
        /// </summary>
        /// <param name="context">The context instance associated with this event.</param>
        /// <returns>A <see cref="Task"/> that can be used to monitor the asynchronous operation.</returns>
        public virtual Task HandleTokenRequest(HandleTokenRequestContext context)
            => OnHandleTokenRequest(context);

        /// <summary>
        /// Represents an event called for each validated userinfo request
        /// to allow the user code to decide how the request should be handled.
        /// </summary>
        /// <param name="context">The context instance associated with this event.</param>
        /// <returns>A <see cref="Task"/> that can be used to monitor the asynchronous operation.</returns>
        public virtual Task HandleUserinfoRequest(HandleUserinfoRequestContext context)
            => OnHandleUserinfoRequest(context);

        /// <summary>
        /// Represents an event called when processing a challenge response.
        /// </summary>
        /// <param name="context">The context instance associated with this event.</param>
        /// <returns>A <see cref="Task"/> that can be used to monitor the asynchronous operation.</returns>
        public virtual Task ProcessChallengeResponse(ProcessChallengeResponseContext context)
            => OnProcessChallengeResponse(context);

        /// <summary>
        /// Represents an event called when processing a sign-in response.
        /// </summary>
        /// <param name="context">The context instance associated with this event.</param>
        /// <returns>A <see cref="Task"/> that can be used to monitor the asynchronous operation.</returns>
        public virtual Task ProcessSigninResponse(ProcessSigninResponseContext context)
            => OnProcessSigninResponse(context);

        /// <summary>
        /// Represents an event called when processing a sign-out response.
        /// </summary>
        /// <param name="context">The context instance associated with this event.</param>
        /// <returns>A <see cref="Task"/> that can be used to monitor the asynchronous operation.</returns>
        public virtual Task ProcessSignoutResponse(ProcessSignoutResponseContext context)
            => OnProcessSignoutResponse(context);

        /// <summary>
        /// Represents an event called before the authorization response is returned to the caller.
        /// </summary>
        /// <param name="context">The context instance associated with this event.</param>
        /// <returns>A <see cref="Task"/> that can be used to monitor the asynchronous operation.</returns>
        public virtual Task ApplyAuthorizationResponse(ApplyAuthorizationResponseContext context)
            => OnApplyAuthorizationResponse(context);

        /// <summary>
        /// Represents an event called before the configuration response is returned to the caller.
        /// </summary>
        /// <param name="context">The context instance associated with this event.</param>
        /// <returns>A <see cref="Task"/> that can be used to monitor the asynchronous operation.</returns>
        public virtual Task ApplyConfigurationResponse(ApplyConfigurationResponseContext context)
            => OnApplyConfigurationResponse(context);

        /// <summary>
        /// Represents an event called before the cryptography response is returned to the caller.
        /// </summary>
        /// <param name="context">The context instance associated with this event.</param>
        /// <returns>A <see cref="Task"/> that can be used to monitor the asynchronous operation.</returns>
        public virtual Task ApplyCryptographyResponse(ApplyCryptographyResponseContext context)
            => OnApplyCryptographyResponse(context);

        /// <summary>
        /// Represents an event called before the introspection response is returned to the caller.
        /// </summary>
        /// <param name="context">The context instance associated with this event.</param>
        /// <returns>A <see cref="Task"/> that can be used to monitor the asynchronous operation.</returns>
        public virtual Task ApplyIntrospectionResponse(ApplyIntrospectionResponseContext context)
            => OnApplyIntrospectionResponse(context);

        /// <summary>
        /// Represents an event called before the logout response is returned to the caller.
        /// </summary>
        /// <param name="context">The context instance associated with this event.</param>
        /// <returns>A <see cref="Task"/> that can be used to monitor the asynchronous operation.</returns>
        public virtual Task ApplyLogoutResponse(ApplyLogoutResponseContext context)
            => OnApplyLogoutResponse(context);

        /// <summary>
        /// Represents an event called before the revocation response is returned to the caller.
        /// </summary>
        /// <param name="context">The context instance associated with this event.</param>
        /// <returns>A <see cref="Task"/> that can be used to monitor the asynchronous operation.</returns>
        public virtual Task ApplyRevocationResponse(ApplyRevocationResponseContext context)
            => OnApplyRevocationResponse(context);

        /// <summary>
        /// Represents an event called before the token response is returned to the caller.
        /// </summary>
        /// <param name="context">The context instance associated with this event.</param>
        /// <returns>A <see cref="Task"/> that can be used to monitor the asynchronous operation.</returns>
        public virtual Task ApplyTokenResponse(ApplyTokenResponseContext context)
            => OnApplyTokenResponse(context);

        /// <summary>
        /// Represents an event called before the userinfo response is returned to the caller.
        /// </summary>
        /// <param name="context">The context instance associated with this event.</param>
        /// <returns>A <see cref="Task"/> that can be used to monitor the asynchronous operation.</returns>
        public virtual Task ApplyUserinfoResponse(ApplyUserinfoResponseContext context)
            => OnApplyUserinfoResponse(context);

        /// <summary>
        /// Represents an event called when serializing an authorization code.
        /// </summary>
        /// <param name="context">The context instance associated with this event.</param>
        /// <returns>A <see cref="Task"/> that can be used to monitor the asynchronous operation.</returns>
        public virtual Task SerializeAuthorizationCode(SerializeAuthorizationCodeContext context)
            => OnSerializeAuthorizationCode(context);

        /// <summary>
        /// Represents an event called when serializing an access token.
        /// </summary>
        /// <param name="context">The context instance associated with this event.</param>
        /// <returns>A <see cref="Task"/> that can be used to monitor the asynchronous operation.</returns>
        public virtual Task SerializeAccessToken(SerializeAccessTokenContext context)
            => OnSerializeAccessToken(context);

        /// <summary>
        /// Represents an event called when serializing an identity token.
        /// </summary>
        /// <param name="context">The context instance associated with this event.</param>
        /// <returns>A <see cref="Task"/> that can be used to monitor the asynchronous operation.</returns>
        public virtual Task SerializeIdentityToken(SerializeIdentityTokenContext context)
            => OnSerializeIdentityToken(context);

        /// <summary>
        /// Represents an event called when serializing a refresh token.
        /// </summary>
        /// <param name="context">The context instance associated with this event.</param>
        /// <returns>A <see cref="Task"/> that can be used to monitor the asynchronous operation.</returns>
        public virtual Task SerializeRefreshToken(SerializeRefreshTokenContext context)
            => OnSerializeRefreshToken(context);

        /// <summary>
        /// Represents an event called when deserializing an authorization code.
        /// </summary>
        /// <param name="context">The context instance associated with this event.</param>
        /// <returns>A <see cref="Task"/> that can be used to monitor the asynchronous operation.</returns>
        public virtual Task DeserializeAuthorizationCode(DeserializeAuthorizationCodeContext context)
            => OnDeserializeAuthorizationCode(context);

        /// <summary>
        /// Represents an event called when deserializing an access token.
        /// </summary>
        /// <param name="context">The context instance associated with this event.</param>
        /// <returns>A <see cref="Task"/> that can be used to monitor the asynchronous operation.</returns>
        public virtual Task DeserializeAccessToken(DeserializeAccessTokenContext context)
            => OnDeserializeAccessToken(context);

        /// <summary>
        /// Represents an event called when deserializing an identity token.
        /// </summary>
        /// <param name="context">The context instance associated with this event.</param>
        /// <returns>A <see cref="Task"/> that can be used to monitor the asynchronous operation.</returns>
        public virtual Task DeserializeIdentityToken(DeserializeIdentityTokenContext context)
            => OnDeserializeIdentityToken(context);

        /// <summary>
        /// Represents an event called when deserializing a refresh token.
        /// </summary>
        /// <param name="context">The context instance associated with this event.</param>
        /// <returns>A <see cref="Task"/> that can be used to monitor the asynchronous operation.</returns>
        public virtual Task DeserializeRefreshToken(DeserializeRefreshTokenContext context)
            => OnDeserializeRefreshToken(context);
    }
}
