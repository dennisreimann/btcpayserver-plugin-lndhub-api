using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using BTCPayServer.Data;
using BTCPayServer.Services.Stores;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace BTCPayServer.Plugins.LNDhubApi.Authentication;

public class LNDhubApiAuthenticationOptions : AuthenticationSchemeOptions;

public class LNDhubApiAuthenticationHandler(
    IOptionsMonitor<IdentityOptions> identityOptions,
    IOptionsMonitor<LNDhubApiAuthenticationOptions> options,
    UserManager<ApplicationUser> userManager,
    LNDhubApiAuthenticator authenticator,
    StoreRepository storeRepository,
    ILoggerFactory logger,
    UrlEncoder encoder)
    : AuthenticationHandler<LNDhubApiAuthenticationOptions>(options, logger, encoder)
{
    private const string AuthHeaderPrefix = "Bearer ";

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        string authHeader = Context.Request.Headers.Authorization;
        if (authHeader == null || !authHeader.StartsWith(AuthHeaderPrefix, StringComparison.InvariantCultureIgnoreCase))
            return AuthenticateResult.NoResult();

        var token = authHeader[AuthHeaderPrefix.Length..];
        var storeId = Context.GetCurrentStoreId();
        var isValid = authenticator.TryParseToken(token, out var userId, out var accessKey);
        var hasAccess = isValid && await authenticator.HasAccess(storeId, token);
        if (!isValid || !hasAccess)
        {
            return AuthenticateResult.Fail("No access");
        }

        // Everything's OK
        var user = await userManager.FindByIdAsync(userId);
        var store = await storeRepository.FindStore(storeId, userId);
        Context.SetStoreData(store);

        var claims = new List<Claim>
        {
            new(identityOptions.CurrentValue.ClaimsIdentity.UserIdClaimType, userId),
            new(LNDhubApiClaimTypes.AccessKey, accessKey),
            new(LNDhubApiClaimTypes.StoreId, store!.Id)
        };
        claims.AddRange((await userManager.GetRolesAsync(user)).Select(s =>
            new Claim(identityOptions.CurrentValue.ClaimsIdentity.RoleClaimType, s)));
        var claimsIdentity = new ClaimsIdentity(claims, LNDhubApiAuthenticationSchemes.AccessKey);
        var principal = new ClaimsPrincipal(claimsIdentity);
        var ticket = new AuthenticationTicket(principal, LNDhubApiAuthenticationSchemes.AccessKey);

        return AuthenticateResult.Success(ticket);
    }
}
