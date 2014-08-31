Owin.Security.OpenIdConnect.Server
==================================

__Owin.Security.OpenIdConnect.Server__ (abbreviated __OSOS__) is an __OpenID Connect server middleware__ that you can use in any OWIN-powered application.

__OSOS__ is specs-compliant and can be used with the official __OpenID Connect client middleware__ developed by Microsoft: https://www.nuget.org/packages/Microsoft.Owin.Security.OpenIdConnect

__The latest nightly build can be found here__: https://www.myget.org/F/aspnet-openidconnect-server/

## Dependencies

The current version relies on the latest version of __Katana 3__ and the __OpenID Connect extensions__ managed by Microsoft that can be found on __NuGet.org__:

https://www.nuget.org/packages/Microsoft.Owin/

https://www.nuget.org/packages/Microsoft.Owin.Security/

https://www.nuget.org/packages/Microsoft.IdentityModel.Protocol.Extensions/

https://www.nuget.org/packages/System.IdentityModel.Tokens.Jwt/

These dependencies are automatically installed in your project if you download __OSOS__ via NuGet.

## Get started

Based on __Microsoft.Owin.Security.OAuth__, __OSOS__ exposes similar primitives and can be directly registered in __Startup.cs__ using the `UseOpenIdConnectServer` extension method:

```csharp
app.UseOpenIdConnectServer(new OpenIdConnectServerOptions {
    Issuer = "http://localhost:55938/",
    SigningCredentials = new X509SigningCredentials(certificate),

    Provider = new CustomOpenIdConnectServerProvider(),
    AuthorizationCodeProvider = new AuthorizationCodeProvider()
});
```

Take a look at https://github.com/AspNet-OpenIdConnect-Server/Owin.Security.OpenIdConnect.Server/tree/dev/samples for a basic sample showing how to configure a new OpenID Connect server using a custom `OpenIdConnectServerProvider` implementation to validate client applications.

## License

This project is licensed under the Apache License.
This means that you can use, modify and distribute it freely.
See http://www.apache.org/licenses/LICENSE-2.0.html for more details.