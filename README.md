AspNet.Security.OpenIdConnect.Server
==================================

**AspNet.Security.OpenIdConnect.Server** is an **advanced OAuth2/OpenID Connect server framework** for both ASP.NET Core 1.0 (previously known as ASP.NET 5) and OWIN/Katana, designed to offer a low-level, protocol-first approach.

**The latest official release can be found on [NuGet](https://www.nuget.org/packages/AspNet.Security.OpenIdConnect.Server) and the nightly builds on [MyGet](https://www.myget.org/gallery/aspnet-contrib)**.

[![Build status](https://ci.appveyor.com/api/projects/status/tyenw4ffs00j4sav/branch/release?svg=true)](https://ci.appveyor.com/project/aspnet-contrib/aspnet-security-openidconnect-server/branch/release)
[![Build status](https://travis-ci.org/aspnet-contrib/AspNet.Security.OpenIdConnect.Server.svg?branch=release)](https://travis-ci.org/aspnet-contrib/AspNet.Security.OpenIdConnect.Server)

## Get started

Based on `OAuthAuthorizationServerMiddleware` from **Katana 3**, **AspNet.Security.OpenIdConnect.Server** exposes similar primitives and can be directly registered in **Startup.cs** using the `UseOpenIdConnectServer` extension method:

```csharp
app.UseOpenIdConnectServer(options => {
    options.Provider = new OpenIdConnectServerProvider {
        // Implement OnValidateAuthorizationRequest to support interactive flows (code/implicit/hybrid).
        OnValidateAuthorizationRequest = context => {
            // Note: you MUST NOT validate the request if client_id is invalid or if redirect_uri
            // doesn't correspond to a trusted URL associated with the client application.
            // You SHOULD also strongly consider validating the type of the client application
            // (public or confidential) to prevent code flow -> implicit flow downgrade attacks.
            if (string.Equals(context.ClientId, "client_id", StringComparison.Ordinal) &&
                string.Equals(context.RedirectUri, "redirect_uri", StringComparison.Ordinal)) {
                context.Validate();
            }

            // Note: if Validate() is not explicitly called,
            // the request is automatically rejected.
            return Task.FromResult(0);
        }

        // Implement OnValidateTokenRequest to support flows using the token endpoint.
        OnValidateTokenRequest = context => {
            // Note: you can skip the request validation when the client_id
            // parameter is missing to support unauthenticated token requests.
            // if (string.IsNullOrEmpty(context.ClientId)) {
            //     context.Skip();
            // }

            // Note: to mitigate brute force attacks, you SHOULD strongly consider applying
            // a key derivation function like PBKDF2 to slow down the secret validation process.
            // You SHOULD also consider using a time-constant comparer to prevent timing attacks.
            if (string.Equals(context.ClientId, "client_id", StringComparison.Ordinal) &&
                string.Equals(context.ClientSecret, "client_secret", StringComparison.Ordinal)) {
                context.Validate();
            }

            // Note: if Validate() is not explicitly called,
            // the request is automatically rejected.
            return Task.FromResult(0);
        }
    };
});
```

## Samples

**Official samples targetting ASP.NET Core 1.0 RC1** can be found on [aspnet-contrib/AspNet.Security.OpenIdConnect.Samples](https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Samples).

**Looking for something simpler?** Don't miss **[OpenIddict](https://github.com/openiddict/core)**, the **simple and easy-to-use OpenID Connect server for ASP.NET Core 1.0** based on AspNet.Security.OpenIdConnect.Server and ASP.NET Identity.

## Support

**Need help or wanna share your thoughts?** Don't hesitate to join our dedicated chat rooms:

- **JabbR: [https://jabbr.net/#/rooms/aspnet-contrib](https://jabbr.net/#/rooms/aspnet-contrib)**
- **Gitter: [https://gitter.im/aspnet-contrib/AspNet.Security.OpenIdConnect.Server](https://gitter.im/aspnet-contrib/AspNet.Security.OpenIdConnect.Server)**

## Contributors

**AspNet.Security.OpenIdConnect.Server** is actively maintained by **[Kévin Chalet](https://github.com/PinpointTownes)**. Contributions are welcome and can be submitted using pull requests.

## License

This project is licensed under the **Apache License**. This means that you can use, modify and distribute it freely. See [http://www.apache.org/licenses/LICENSE-2.0.html](http://www.apache.org/licenses/LICENSE-2.0.html) for more details.