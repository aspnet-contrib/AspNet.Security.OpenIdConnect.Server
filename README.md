Owin.Security.OpenIdConnect.Server
==================================

OpenIdConnect-Server-Implementation reviewed by the team of Microsoft.Owin ("Katana")

You can use this middleware to implement an OpenId Connect Server, that works with Microsoft's OpenId-Connect-Client-Middleware. 

## Dependencies

The current version uses a nightly build of Katana (Microsoft.Owin) that can be found in the NuGet-Repository https://www.myget.org/f/aspnetwebstacknightly/

The final version will use the final build of Katana V3.

## Register Middleware

The following sample shows how to register this middleware. Have a look at the sample-project _SampleOpenIdConnectServer_ to find
more information about the following referenced classes and cshtml-files: _auth.cshtml,_ _FormPost.cshtml_, _TestAuthenticationTokenProvider_ and _CustomOAuthProvider_. 

The file _auth.cshtml_ logs in a demo-user. In a real-world-implementation, this file would show a login-form. 

The file _FormPost.cshtml_ is used to implement response_mode=form_post. Further versions of Katana's OAuth-Implementation may not need/ support this property and implement form_post in a more direct way.

```C#
var key = new InMemorySymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes("secret_secret_secret"));

app.UseOpenIdConnectAuthorizationServer(new OpenIdConnectServerOptions
{
    IdTokenExpireTimeSpan = TimeSpan.FromMinutes(60),
    IssuerName = "urn:authServer",
    SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256Signature, SecurityAlgorithms.Sha256Digest),
    TokenEndpointPath = new PathString("/token"),
    AuthorizeEndpointPath = new PathString("/auth.cshtml"),
    FormPostEndpoint = new PathString("/FormPost.cshtml"),
    Provider = new CustomOAuthProvider(),
    AccessTokenExpireTimeSpan = TimeSpan.FromDays(14),
    AllowInsecureHttp = true,
    ApplicationCanDisplayErrors = true,
    AuthorizationCodeProvider = new TestAuthenticationTokenProvider(),
    RefreshTokenProvider = new TestAuthenticationTokenProvider(),
});
```

## Testing the middleware

To test the Server start the sample-application and use something like fiddler to access 

	http://localhost:18001/Katana.Sandbox.WebServer/auth.cshtml?response_type=code+id_token&client_id=myClient&state=xyz&redirect_uri=http%3A%2F%2Flocalhost%3A6980%2Foidc&nonce=1234&scope=openid&response_mode=form_post

You should get back an id_token using post to the url that is included in this call.

## Use the middleware with Microsoft's OpenId-Connect-Client-Middleware

The following listing shows a Owin-Configuration that configures Microsoft's OpenId-Connect-Client-Middleware (NuGet-Package _Microsoft.Owin.Security.OpenIdConnect_) for the usage with the here described Server-Middleware. Have a look at the sample-project _SampleOpenIdConnectClient_ for more infos.

```C#
app.UseExternalSignInCookie("ExternalCookie");

var key = new InMemorySymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes("secret_secret_secret"));

app.UseOpenIdConnectAuthentication(new OpenIdConnectAuthenticationOptions {
    AuthenticationMode = AuthenticationMode.Active,
    AuthenticationType = "OIDC",
    SignInAsAuthenticationType = "ExternalCookie",
    ClientId = "myClient",
    ClientSecret = "secret_secret_secret",
    RedirectUri = "http://localhost:57264/oidc",
    Scope = "openid",
    Configuration = new OpenIdConnectConfiguration
    {
        AuthorizationEndpoint = "http://localhost:59504/auth.cshtml",
        TokenEndpoint = "http://localhost:59504/token"
    },
    TokenValidationParameters = new TokenValidationParameters()
    {
        ValidAudience = "myClient",
        ValidIssuer = "urn:authServer",
        IssuerSigningKey = key
    }
});
```

You can use the following snipped within the application-code to authenticate the user with the middleware. After a successful authentication, the variable _result_ provides a _ClaimsIdentity_ describing the current user via it's property _Identity_.

```C#
var result = Request.GetOwinContext().Authentication.AuthenticateAsync("ExternalCookie").Result;

if (result == null)
{
    Request.GetOwinContext().Authentication.Challenge("OIDC");
}
```
