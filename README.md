# ASP.NET Core HTTP-header authentication middleware
[![Visus.HeaderAuthentication](https://img.shields.io/nuget/v/Visus.HeaderAuthentication.svg)](https://www.nuget.org/packages/Visus.HeaderAuthentication)

This library implements middleware to add authentication schemes bases on HTTP headers to an ASP.NET Core application.

## Usage
In your application setup, add something like this:
```C#
builder.Services.AddHeaderAuthentication("MyScheme", o => {
    o.HeaderHandler = new BasicHeaderHandler("MyScheme", new Dictionary<string, string> {
        { "user1", "password1" },
        { "user2", "password2" }
    });

    // The following changes the header processed by the authentication
    // handler. If not customised, the standard "Authorization" header is
    // used.
    o.HeaderName = "Auth";
});
```

The `HeaderHandler` is an implementation of the `Visus.HeaderAuthentication.Handlers.IHeaderHandler` interface which creates claims from the configured header values. The library supplies a handler for the basic authentication scheme and a "Token".

Instead of hard coding the users, you can add callbacks to `BasicHeaderHandler` and `TokenHeaderHandler`, which allow for lookup of users and tokens in other sources like databases. You could also combine this method with [Visus.LdapAuthentication](https://github.com/UniStuttgart-VISUS/Visus.LdapAuthentication) as backend for looking up users. Setting a custom callback also allows for customising the `Sytstem.Security.Claims.Claim`s created for a successfully authenticated user.
