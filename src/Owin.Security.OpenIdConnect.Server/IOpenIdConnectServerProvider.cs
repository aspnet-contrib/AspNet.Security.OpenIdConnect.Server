/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System.Threading.Tasks;
using Microsoft.Owin.Security.Notifications;

namespace Owin.Security.OpenIdConnect.Server {
    /// <summary>
    /// Interface used by the authorization server to communicate with the web application while processing requests.
    /// Implementers are strongly encouraged to use the default <see cref="OpenIdConnectServerProvider"/>
    /// implementation to avoid breaking changes in the future.
    /// </summary>
    public interface IOpenIdConnectServerProvider {
        /// <summary>
        /// Called to determine if an incoming request is treated as an authorization or token
        /// endpoint. If Options.AuthorizationEndpointPath or Options.TokenEndpointPath
        /// are assigned values, then handling this event is optional and context.IsAuthorizationEndpoint and context.IsTokenEndpoint
        /// will already be true if the request path matches.
        /// </summary>
        /// <param name="context">The context of the event carries information in and results out.</param>
        /// <returns>Task to enable asynchronous execution</returns>
        Task MatchEndpoint(MatchEndpointContext context);

        /// <summary>
        /// Called for each request to the authorization endpoint to determine if the request is valid and should continue.
        /// </summary>
        /// <param name="context">The context of the event carries information in and results out.</param>
        /// <returns>Task to enable asynchronous execution</returns>
        Task ValidateAuthorizationRequest(ValidateAuthorizationRequestContext context);

        /// <summary>
        /// Called for each request to the configuration endpoint to determine if the request is valid and should continue.
        /// </summary>
        /// <param name="context">The context of the event carries information in and results out.</param>
        /// <returns>Task to enable asynchronous execution</returns>
        Task ValidateConfigurationRequest(ValidateConfigurationRequestContext context);

        /// <summary>
        /// Called for each request to the cryptography endpoint to determine if the request is valid and should continue.
        /// </summary>
        /// <param name="context">The context of the event carries information in and results out.</param>
        /// <returns>Task to enable asynchronous execution</returns>
        Task ValidateCryptographyRequest(ValidateCryptographyRequestContext context);

        /// <summary>
        /// Called for each request to the introspection endpoint to determine if the request is valid and should continue.
        /// </summary>
        /// <param name="context">The context of the event carries information in and results out.</param>
        /// <returns>Task to enable asynchronous execution</returns>
        Task ValidateIntrospectionRequest(ValidateIntrospectionRequestContext context);

        /// <summary>
        /// Called for each request to the revocation endpoint to determine if the request is valid and should continue.
        /// </summary>
        /// <param name="context">The context of the event carries information in and results out.</param>
        /// <returns>Task to enable asynchronous execution</returns>
        Task ValidateRevocationRequest(ValidateRevocationRequestContext context);

        /// <summary>
        /// Called for each request to the logout endpoint to determine if the request is valid and should continue.
        /// </summary>
        /// <param name="context">The context of the event carries information in and results out.</param>
        /// <returns>Task to enable asynchronous execution</returns>
        Task ValidateLogoutRequest(ValidateLogoutRequestContext context);

        /// <summary>
        /// Called for each request to the token endpoint to determine if the request is valid and should continue.
        /// </summary>
        /// <param name="context">The context of the event carries information in and results out.</param>
        /// <returns>Task to enable asynchronous execution</returns>
        Task ValidateTokenRequest(ValidateTokenRequestContext context);

        /// <summary>
        /// Called for each request to the userinfo endpoint to determine if the request is valid and should continue.
        /// </summary>
        /// <param name="context">The context of the event carries information in and results out.</param>
        /// <returns>Task to enable asynchronous execution</returns>
        Task ValidateUserinfoRequest(ValidateUserinfoRequestContext context);

        /// <summary>
        /// Called at the final stage of an incoming authorization endpoint request before the execution continues on to the web application component 
        /// responsible for producing the html response. Anything present in the OWIN pipeline following the Authorization Server may produce the
        /// response for the authorization page. If running on IIS any ASP.NET technology running on the server may produce the response for the 
        /// authorization page. If the web application wishes to produce the response directly in the AuthorizationEndpoint call it may write to the 
        /// context.Response directly and should call context.RequestCompleted to stop other handlers from executing. If the web application wishes
        /// to grant the authorization directly in the AuthorizationEndpoint call it cay call context.OwinContext.Authentication.SignIn with the
        /// appropriate ClaimsIdentity and should call context.RequestCompleted to stop other handlers from executing.
        /// </summary>
        /// <param name="context">The context of the event carries information in and results out.</param>
        /// <returns>Task to enable asynchronous execution</returns>
        Task HandleAuthorizationRequest(HandleAuthorizationRequestContext context);

        /// <summary>
        /// Called by the client applications to retrieve the OpenID Connect configuration associated with this instance.
        /// An application may implement this call in order to do any final modification to the configuration metadata.
        /// </summary>
        /// <param name="context">The context of the event carries information in and results out.</param>
        /// <returns>Task to enable asynchronous execution</returns>
        Task HandleConfigurationRequest(HandleConfigurationRequestContext context);

        /// <summary>
        /// Called by the client applications to retrieve the OpenID Connect JSON Web Key set associated with this instance.
        /// An application may implement this call in order to do any final modification to the keys set.
        /// </summary>
        /// <param name="context">The context of the event carries information in and results out.</param>
        /// <returns>Task to enable asynchronous execution</returns>
        Task HandleCryptographyRequest(HandleCryptographyRequestContext context);

        /// <summary>
        /// Called by the client applications to determine the status and metadata about a token.
        /// Validation conforms to the OAuth 2.0 Token Introspection specification with some additions. See documentation for details.
        /// An application may implement this call in order to do any final modification to the token status and metadata.
        /// </summary>
        /// <param name="context">The context of the event carries information in and results out.</param>
        /// <returns>Task to enable asynchronous execution</returns>
        Task HandleIntrospectionRequest(HandleIntrospectionRequestContext context);

        /// <summary>
        /// Called at the final stage of an incoming logout endpoint request before the execution continues on to the web application component 
        /// responsible for producing the html response. Anything present in the OWIN pipeline following the Authorization Server may produce the
        /// response for the logout page. If running on IIS any ASP.NET technology running on the server may produce the response for the 
        /// authorization page. If the web application wishes to produce the response directly in the LogoutEndpoint call it may write to the 
        /// context.Response directly and should call context.RequestCompleted to stop other handlers from executing.
        /// </summary>
        /// <param name="context">The context of the event carries information in and results out.</param>
        /// <returns>Task to enable asynchronous execution</returns>
        Task HandleLogoutRequest(HandleLogoutRequestContext context);

        /// <summary>
        /// Called by the client applications to revoke an access or refresh token.
        /// An application may implement this call in order to do any final modification to the revocation response.
        /// </summary>
        /// <param name="context">The context of the event carries information in and results out.</param>
        /// <returns>Task to enable asynchronous execution</returns>
        Task HandleRevocationRequest(HandleRevocationRequestContext context);

        /// <summary>
        /// Called at the final stage of a successful Token endpoint request.
        /// An application may implement this call in order to do any final 
        /// modification of the claims being used to issue access or refresh tokens. 
        /// </summary>
        /// <param name="context">The context of the event carries information in and results out.</param>
        /// <returns>Task to enable asynchronous execution</returns>
        Task HandleTokenRequest(HandleTokenRequestContext context);

        /// <summary>
        /// Called at the final stage of an incoming userinfo endpoint request before the execution continues on to the web application component 
        /// responsible for producing the JSON response. Anything present in the OWIN pipeline following the Authorization Server may produce the
        /// response for the userinfo response. If the web application wishes to produce the response directly in the UserinfoEndpoint call it
        /// may write to the context.Response directly and should call context.HandleResponse to stop other handlers from executing.
        /// </summary>
        /// <param name="context">The context of the event carries information in and results out.</param>
        /// <returns>Task to enable asynchronous execution</returns>
        Task HandleUserinfoRequest(HandleUserinfoRequestContext context);

        /// <summary>
        /// Called before the AuthorizationEndpoint redirects its response to the caller.
        /// The response could contain an access token when using implicit flow or
        /// an authorization code when using the authorization code flow.
        /// If the web application wishes to produce the authorization response directly in the AuthorizationEndpoint call it may write to the 
        /// context.Response directly and should call context.RequestCompleted to stop other handlers from executing.
        /// This call may also be used to add additional response parameters to the authorization response.
        /// </summary>
        /// <param name="context">The context of the event carries information in and results out.</param>
        /// <returns>Task to enable asynchronous execution</returns>
        Task ApplyAuthorizationResponse(ApplyAuthorizationResponseContext context);

        /// <summary>
        /// Called before the authorization server starts emitting the OpenID Connect configuration associated with this instance.
        /// If the web application wishes to produce the configuration metadata directly in this call, it may write to the 
        /// context.Response directly and should call context.RequestCompleted to stop the default behavior from executing.
        /// </summary>
        /// <param name="context">The context of the event carries information in and results out.</param>
        /// <returns>Task to enable asynchronous execution</returns>
        Task ApplyConfigurationResponse(ApplyConfigurationResponseContext context);

        /// <summary>
        /// Called before the authorization server starts emitting the OpenID Connect JSON Web Key set associated with this instance.
        /// If the web application wishes to produce the JSON Web Key set directly in this call, it may write to the 
        /// context.Response directly and should call context.RequestCompleted to stop the default behavior from executing.
        /// </summary>
        /// <param name="context">The context of the event carries information in and results out.</param>
        /// <returns>Task to enable asynchronous execution</returns>
        Task ApplyCryptographyResponse(ApplyCryptographyResponseContext context);

        /// <summary>
        /// Called before the authorization server starts emitting the status and metadata associated with the token received.
        /// Validation conforms to the OAuth 2.0 Token Introspection specification with some additions. See documentation for details.
        /// If the web application wishes to produce the token status and metadata directly in this call, it may write to the 
        /// context.Response directly and should call context.RequestCompleted to stop the default behavior from executing.
        /// </summary>
        /// <param name="context">The context of the event carries information in and results out.</param>
        /// <returns>Task to enable asynchronous execution</returns>
        Task ApplyIntrospectionResponse(ApplyIntrospectionResponseContext context);

        /// <summary>
        /// Called before the LogoutEndpoint endpoint redirects its response to the caller.
        /// If the web application wishes to produce the authorization response directly in the LogoutEndpoint call it may write to the 
        /// context.Response directly and should call context.RequestCompleted to stop other handlers from executing.
        /// This call may also be used to add additional response parameters to the authorization response.
        /// </summary>
        /// <param name="context">The context of the event carries information in and results out.</param>
        /// <returns>Task to enable asynchronous execution</returns>
        Task ApplyLogoutResponse(ApplyLogoutResponseContext context);

        /// <summary>
        /// Called before the authorization server starts emitting the revocation response to the response stream.
        /// If the web application wishes to produce the token status and metadata directly in this call, it may write to the 
        /// context.Response directly and should call context.RequestCompleted to stop the default behavior from executing.
        /// </summary>
        /// <param name="context">The context of the event carries information in and results out.</param>
        /// <returns>Task to enable asynchronous execution</returns>
        Task ApplyRevocationResponse(ApplyRevocationResponseContext context);

        /// <summary>
        /// Called before the TokenEndpoint redirects its response to the caller.
        /// This call may also be used in order to add additional 
        /// response parameters to the JSON response payload.
        /// </summary>
        /// <param name="context">The context of the event carries information in and results out.</param>
        /// <returns>Task to enable asynchronous execution</returns>
        Task ApplyTokenResponse(ApplyTokenResponseContext context);

        /// <summary>
        /// Called before the UserinfoEndpoint endpoint starts writing to the response stream.
        /// If the web application wishes to produce the userinfo response directly in the UserinfoEndpoint call it may write to the 
        /// context.Response directly and should call context.RequestCompleted to stop other handlers from executing.
        /// This call may also be used to add additional response parameters to the authorization response.
        /// </summary>
        /// <param name="context">The context of the event carries information in and results out.</param>
        /// <returns>Task to enable asynchronous execution</returns>
        Task ApplyUserinfoResponse(ApplyUserinfoResponseContext context);

        /// <summary>
        /// Called to create a new authorization code. An application may use this context
        /// to replace the authentication ticket before it is serialized or to use its own code store
        /// and skip the default logic using <see cref="BaseNotification{OpenIdConnectServerOptions}.HandleResponse"/>.
        /// </summary>
        /// <param name="context">The context of the event carries information in and results out.</param>
        /// <returns>Task to enable asynchronous execution</returns>
        Task SerializeAuthorizationCode(SerializeAuthorizationCodeContext context);

        /// <summary>
        /// Called to create a new access token. An application may use this context
        /// to replace the authentication ticket before it is serialized or to use its own token format
        /// and skip the default logic using <see cref="BaseNotification{OpenIdConnectServerOptions}.HandleResponse"/>.
        /// </summary>
        /// <param name="context">The context of the event carries information in and results out.</param>
        /// <returns>Task to enable asynchronous execution</returns>
        Task SerializeAccessToken(SerializeAccessTokenContext context);

        /// <summary>
        /// Called to create a new identity token. An application may use this context
        /// to replace the authentication ticket before it is serialized or to use its own token format
        /// and skip the default logic using <see cref="BaseNotification{OpenIdConnectServerOptions}.HandleResponse"/>.
        /// </summary>
        /// <param name="context">The context of the event carries information in and results out.</param>
        /// <returns>Task to enable asynchronous execution</returns>
        Task SerializeIdentityToken(SerializeIdentityTokenContext context);

        /// <summary>
        /// Called to create a new refresh token. An application may use this context
        /// to replace the authentication ticket before it is serialized or to use its own token format
        /// and skip the default logic using <see cref="BaseNotification{OpenIdConnectServerOptions}.HandleResponse"/>.
        /// </summary>
        /// <param name="context">The context of the event carries information in and results out.</param>
        /// <returns>Task to enable asynchronous execution</returns>
        Task SerializeRefreshToken(SerializeRefreshTokenContext context);

        /// <summary>
        /// Called when receiving an authorization code. An application may use this context
        /// to deserialize the code using a custom format and to skip the default logic using
        /// <see cref="BaseNotification{OpenIdConnectServerOptions}.HandleResponse"/>.
        /// </summary>
        /// <param name="context">The context of the event carries information in and results out.</param>
        /// <returns>Task to enable asynchronous execution</returns>
        Task DeserializeAuthorizationCode(DeserializeAuthorizationCodeContext context);

        /// <summary>
        /// Called when receiving an access token. An application may use this context
        /// to deserialize the token using a custom format and to skip the default logic using
        /// <see cref="BaseNotification{OpenIdConnectServerOptions}.HandleResponse"/>.
        /// </summary>
        /// <param name="context">The context of the event carries information in and results out.</param>
        /// <returns>Task to enable asynchronous execution</returns>
        Task DeserializeAccessToken(DeserializeAccessTokenContext context);

        /// <summary>
        /// Called when receiving an identity token. An application may use this context
        /// to deserialize the token using a custom format and to skip the default logic using
        /// <see cref="BaseNotification{OpenIdConnectServerOptions}.HandleResponse"/>.
        /// </summary>
        /// <param name="context">The context of the event carries information in and results out.</param>
        /// <returns>Task to enable asynchronous execution</returns>
        Task DeserializeIdentityToken(DeserializeIdentityTokenContext context);

        /// <summary>
        /// Called when receiving a refresh token. An application may use this context
        /// to deserialize the code using a custom format and to skip the default logic using
        /// <see cref="BaseNotification{OpenIdConnectServerOptions}.HandleResponse"/>.
        /// </summary>
        /// <param name="context">The context of the event carries information in and results out.</param>
        /// <returns>Task to enable asynchronous execution</returns>
        Task DeserializeRefreshToken(DeserializeRefreshTokenContext context);
    }
}
