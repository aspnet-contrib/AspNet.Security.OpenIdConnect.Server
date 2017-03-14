AspNet.Security.OpenIdConnect.Server
==================================

**AspNet.Security.OpenIdConnect.Server** is an **advanced OAuth2/OpenID Connect server framework** for both ASP.NET Core 1.0 (previously known as ASP.NET 5) and OWIN/Katana, designed to offer a low-level, protocol-first approach.

**The latest official release can be found on [NuGet](https://www.nuget.org/packages/AspNet.Security.OpenIdConnect.Server) and the nightly builds on [MyGet](https://www.myget.org/gallery/aspnet-contrib)**.

[![Build status](https://ci.appveyor.com/api/projects/status/tyenw4ffs00j4sav/branch/dev?svg=true)](https://ci.appveyor.com/project/aspnet-contrib/aspnet-security-openidconnect-server/branch/dev)
[![Build status](https://travis-ci.org/aspnet-contrib/AspNet.Security.OpenIdConnect.Server.svg?branch=dev)](https://travis-ci.org/aspnet-contrib/AspNet.Security.OpenIdConnect.Server)

## Get started

Based on `OAuthAuthorizationServerMiddleware` from **Katana 3**, **AspNet.Security.OpenIdConnect.Server** exposes similar primitives and can be directly registered in **Startup.cs** using the `UseOpenIdConnectServer` extension method:

```csharp
app.UseOpenIdConnectServer(options =>
{
    // Enable the token endpoint.
    options.TokenEndpointPath = "/connect/token";

    // Implement OnValidateTokenRequest to support flows using the token endpoint.
    options.Provider.OnValidateTokenRequest = context =>
    {
        // Reject token requests that don't use grant_type=password or grant_type=refresh_token.
        if (!context.Request.IsPasswordGrantType() && !context.Request.IsRefreshTokenGrantType())
        {
            context.Reject(
                error: OpenIdConnectConstants.Errors.UnsupportedGrantType,
                description: "Only grant_type=password and refresh_token " +
                             "requests are accepted by this server.");

            return Task.FromResult(0);
        }

        // Note: you can skip the request validation when the client_id
        // parameter is missing to support unauthenticated token requests.
        // if (string.IsNullOrEmpty(context.ClientId))
        // {
        //     context.Skip();
        // 
        //     return Task.FromResult(0);
        // }

        // Note: to mitigate brute force attacks, you SHOULD strongly consider applying
        // a key derivation function like PBKDF2 to slow down the secret validation process.
        // You SHOULD also consider using a time-constant comparer to prevent timing attacks.
        if (string.Equals(context.ClientId, "client_id", StringComparison.Ordinal) &&
            string.Equals(context.ClientSecret, "client_secret", StringComparison.Ordinal))
        {
            context.Validate();
        }

        // Note: if Validate() is not explicitly called,
        // the request is automatically rejected.
        return Task.FromResult(0);
    };

    // Implement OnHandleTokenRequest to support token requests.
    options.Provider.OnHandleTokenRequest = context =>
    {
        // Only handle grant_type=password token requests and let the
        // OpenID Connect server middleware handle the other grant types.
        if (context.Request.IsPasswordGrantType())
        {
            // Implement context.Request.Username/context.Request.Password validation here.
            // Note: you can call context Reject() to indicate that authentication failed.
            // Using password derivation and time-constant comparer is STRONGLY recommended.
            if (!string.Equals(context.Request.Username, "Bob", StringComparison.Ordinal) ||
                !string.Equals(context.Request.Password, "P@ssw0rd", StringComparison.Ordinal))
            {
                context.Reject(
                    error: OpenIdConnectConstants.Errors.InvalidGrant,
                    description: "Invalid user credentials.");

                return Task.FromResult(0);
            }

            var identity = new ClaimsIdentity(context.Options.AuthenticationScheme,
                OpenIdConnectConstants.Claims.Name,
                OpenIdConnectConstants.Claims.Role);

            // Add the mandatory subject/user identifier claim.
            identity.AddClaim(OpenIdConnectConstants.Claims.Subject, "[unique id]");

            // By default, claims are not serialized in the access/identity tokens.
            // Use the overload taking a "destinations" parameter to make sure
            // your claims are correctly inserted in the appropriate tokens.
            identity.AddClaim("urn:customclaim", "value",
                OpenIdConnectConstants.Destinations.AccessToken,
                OpenIdConnectConstants.Destinations.IdentityToken);

            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(identity),
                new AuthenticationProperties(),
                context.Options.AuthenticationScheme);

            // Call SetScopes with the list of scopes you want to grant
            // (specify offline_access to issue a refresh token).
            ticket.SetScopes(
                OpenIdConnectConstants.Scopes.Profile,
                OpenIdConnectConstants.Scopes.OfflineAccess);

            context.Validate(ticket);
        }

        return Task.FromResult(0);
    };
});
```

> Note: in order for the OpenID Connect server middleware to work properly, **the authentication services must be registered in the DI container**:

```csharp
public void ConfigureServices(IServiceCollection services)
{
    services.AddAuthentication();
}
```

## Resources

**Looking for additional resources to help you get started?** Don't miss these interesting blog posts:

- **[Creating your own OpenID Connect server with ASOS](http://kevinchalet.com/2016/07/13/creating-your-own-openid-connect-server-with-asos-introduction/)** by [Kévin Chalet](https://github.com/PinpointTownes)

## Samples

The samples found [in the current project](./samples/) directory always target the latest ASP.NET Core releases and are mainly meant to ease its testing.

**Official samples targetting ASP.NET Core 1.0 RTM** can be found on [aspnet-contrib/AspNet.Security.OpenIdConnect.Samples](https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Samples). 

**Looking for something simpler?** Don't miss **[OpenIddict](https://github.com/openiddict/core)**, the **simple and easy-to-use OpenID Connect server for ASP.NET Core 1.0** based on AspNet.Security.OpenIdConnect.Server and ASP.NET Core Identity.

## Support

**Need help or wanna share your thoughts?** Don't hesitate to join us on Gitter or ask your question on StackOverflow:

- **Gitter: [https://gitter.im/aspnet-contrib/AspNet.Security.OpenIdConnect.Server](https://gitter.im/aspnet-contrib/AspNet.Security.OpenIdConnect.Server)**
- **StackOverflow: [https://stackoverflow.com/questions/tagged/aspnet-contrib](https://stackoverflow.com/questions/tagged/aspnet-contrib)**

## Contributors

**AspNet.Security.OpenIdConnect.Server** is actively maintained by **[Kévin Chalet](https://github.com/PinpointTownes)**. Contributions are welcome and can be submitted using pull requests.

## License

This project is licensed under the **Apache License**. This means that you can use, modify and distribute it freely. See [http://www.apache.org/licenses/LICENSE-2.0.html](http://www.apache.org/licenses/LICENSE-2.0.html) for more details.
