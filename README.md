AspNet.Security.OpenIdConnect.Server
==================================

__AspNet.Security.OpenIdConnect.Server__ is an __OpenID Connect server middleware__ that you can use in any ASP.NET 5 application and that works with the official __OpenID Connect client middleware__ developed by _Microsoft_ or any __standards-compliant OAuth2/OpenID Connect client__.

__The latest nightly builds can be found here__: https://www.myget.org/F/aspnet-openidconnect-server/

## Dependencies

The current version relies on the latest version of __ASP.NET 5__ and the __OpenID Connect extensions__ managed by the _Microsoft Azure AD_ that can be found on __MyGet.org__:

* https://www.myget.org/gallery/aspnetvnext

* https://www.myget.org/gallery/azureadwebstacknightly

## Get started

Based on `OAuthAuthorizationServerMiddleware` from Katana 3, __AspNet.Security.OpenIdConnect.Server__ exposes similar primitives and can be directly registered in __Startup.cs__ using the `UseOpenIdConnectServer` extension method:

```csharp
app.UseOpenIdConnectServer(options => {
    options.Issuer = "http://localhost:55938/";
    options.SigningCredentials = new SigningCredentials(
        new X509SecurityKey(certificate),
        SecurityAlgorithms.RsaSha256Signature,
        SecurityAlgorithms.Sha256Digest);

    options.Provider = new CustomOpenIdConnectServerProvider();
    options.AuthorizationCodeProvider = new AuthorizationCodeProvider();
});
```

Take a look at https://github.com/aspnet-security/AspNet.Security.OpenIdConnect.Server/tree/vNext/samples/Mvc for a sample using MVC 6 and showing how to configure a new OpenID Connect server using a custom `OpenIdConnectServerProvider` implementation to validate client applications.

## License

This project is licensed under the Apache License.
This means that you can use, modify and distribute it freely.
See http://www.apache.org/licenses/LICENSE-2.0.html for more details.