Owin.Security.OpenIdConnect.Server
==================================

**Owin.Security.OpenIdConnect.Server** is an **OpenID Connect server middleware** that you can use in **any OWIN-powered application** and that works with the official **OpenID Connect client middleware** developed by Microsoft or with any **standards-compliant OAuth2/OpenID Connect client**.

**The latest official release can be found on [NuGet](https://www.nuget.org/packages/Owin.Security.OpenIdConnect.Server) and the nightly builds on [MyGet](https://www.myget.org/gallery/aspnet-contrib)**.

[![Build status](https://ci.appveyor.com/api/projects/status/tyenw4ffs00j4sav/branch/dev?svg=true)](https://ci.appveyor.com/project/aspnet-contrib/aspnet-security-openidconnect-server/branch/dev)
[![Build status](https://travis-ci.org/aspnet-contrib/AspNet.Security.OpenIdConnect.Server.svg?branch=dev)](https://travis-ci.org/aspnet-contrib/AspNet.Security.OpenIdConnect.Server)

## Get started

Based on **Microsoft.Owin.Security.OAuth**, **Owin.Security.OpenIdConnect.Server** exposes similar primitives and can be directly registered in **Startup.cs** using the `UseOpenIdConnectServer` extension method:

```csharp
app.UseOpenIdConnectServer(options => {
    options.Provider = new OpenIdConnectServerProvider {
        // Implement OnValidateClientRedirectUri to support interactive flows like code/implicit/hybrid.
        OnValidateClientRedirectUri = context => {
            if (string.Equals(context.ClientId, "client_id", StringComparison.Ordinal) &&
                string.Equals(context.RedirectUri, "redirect_uri", StringComparison.Ordinal)) {
                context.Validate();
            }

            return Task.FromResult(0);
        }

        // Implement OnValidateClientAuthentication to support flows using the token endpoint.
        OnValidateClientAuthentication = context => {
            if (string.Equals(context.ClientId, "client_id", StringComparison.Ordinal) &&
                string.Equals(context.ClientSecret, "client_secret", StringComparison.Ordinal)) {
                context.Validate();
            }

            return Task.FromResult(0);
        }
    };
});
```

See [https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server/tree/dev/samples/Mvc](https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server/tree/dev/samples/Mvc) for a sample **using MVC 6 and showing how to configure a new OpenID Connect server using a custom `OpenIdConnectServerProvider` implementation to validate client applications**.

## Support

**Need help or wanna share your thoughts? Don't hesitate to join our dedicated chat rooms:**

- **JabbR: [https://jabbr.net/#/rooms/aspnet-contrib](https://jabbr.net/#/rooms/aspnet-contrib)**
- **Gitter: [https://gitter.im/aspnet-contrib/AspNet.Security.OpenIdConnect.Server](https://gitter.im/aspnet-contrib/AspNet.Security.OpenIdConnect.Server)**

## Contributors

**Owin.Security.OpenIdConnect.Server** is actively maintained by **[Kévin Chalet](https://github.com/PinpointTownes)**. Contributions are welcome and can be submitted using pull requests.

## License

This project is licensed under the **Apache License**. This means that you can use, modify and distribute it freely. See [http://www.apache.org/licenses/LICENSE-2.0.html](http://www.apache.org/licenses/LICENSE-2.0.html) for more details.