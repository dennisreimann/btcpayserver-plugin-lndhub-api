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

public class LNDhubApiAuthenticationOptions : AuthenticationSchemeOptions
{
}

public class LNDhubApiAuthenticationHandler : AuthenticationHandler<LNDhubApiAuthenticationOptions>
{
    private const string AuthHeaderPrefix = "Bearer ";
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IOptionsMonitor<IdentityOptions> _identityOptions;
    private readonly LNDhubApiAuthenticator _authenticator;
    private readonly StoreRepository _storeRepository;

    public LNDhubApiAuthenticationHandler(
        IOptionsMonitor<IdentityOptions> identityOptions,
        IOptionsMonitor<LNDhubApiAuthenticationOptions> options,
        UserManager<ApplicationUser> userManager,
        LNDhubApiAuthenticator authenticator,
        StoreRepository storeRepository,
        ILoggerFactory logger,
        UrlEncoder encoder,
        ISystemClock clock) : base(options, logger, encoder, clock)
    {
        _storeRepository = storeRepository;
        _identityOptions = identityOptions;
        _authenticator = authenticator;
        _userManager = userManager;
    }

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        string authHeader = Context.Request.Headers["Authorization"];
        if (authHeader == null || !authHeader.StartsWith(AuthHeaderPrefix, StringComparison.InvariantCultureIgnoreCase))
            return AuthenticateResult.NoResult();

        var token = authHeader[AuthHeaderPrefix.Length..];
        var storeId = Context.GetCurrentStoreId();
        var isValid = _authenticator.TryParseToken(token, out var userId, out var accessKey);
        var hasAccess = isValid && await _authenticator.HasAccess(storeId, token);
        if (!isValid || !hasAccess)
        {
            return AuthenticateResult.Fail("No access");
        }

        // Everything's OK
        var user = await _userManager.FindByIdAsync(userId);
        var store = await _storeRepository.FindStore(storeId, userId);
        Context.SetStoreData(store);

        var claims = new List<Claim>
        {
            new(_identityOptions.CurrentValue.ClaimsIdentity.UserIdClaimType, userId),
            new(LNDhubApiClaimTypes.AccessKey, accessKey),
            new(LNDhubApiClaimTypes.StoreId, store!.Id)
        };
        claims.AddRange((await _userManager.GetRolesAsync(user)).Select(s =>
            new Claim(_identityOptions.CurrentValue.ClaimsIdentity.RoleClaimType, s)));
        var claimsIdentity = new ClaimsIdentity(claims, LNDhubApiAuthenticationSchemes.AccessKey);
        var principal = new ClaimsPrincipal(claimsIdentity);
        var ticket = new AuthenticationTicket(principal, LNDhubApiAuthenticationSchemes.AccessKey);

        return AuthenticateResult.Success(ticket);
    }
}
