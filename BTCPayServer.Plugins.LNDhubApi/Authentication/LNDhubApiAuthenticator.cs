using System.Threading.Tasks;
using BTCPayServer.Client;
using BTCPayServer.Data;
using BTCPayServer.Plugins.LNDhubApi.Models;
using BTCPayServer.Services.Stores;
using Microsoft.AspNetCore.Identity;

namespace BTCPayServer.Plugins.LNDhubApi.Authentication;

public class LNDhubApiAuthenticator(StoreRepository storeRepository, UserManager<ApplicationUser> userManager)
{
    public async Task<string?> AccessToken(string storeId, string? login, string? password)
    {
        if (string.IsNullOrEmpty(login) || string.IsNullOrEmpty(password)) return null;
        // login = user id, password = access key
        var user = await userManager.FindByIdAsync(login);
        var store = await storeRepository.FindStore(storeId, user!.Id);
        var settings = store != null ? await storeRepository.GetSettingAsync<LNDhubApiSettings>(store.Id, LNDhubApiPlugin.SettingsKey) : null;
        var accessToken = settings is { Enabled: true } ? settings.AccessToken : null;
        var accessTokenMatches = accessToken != null && accessToken == password;
        var role = store?.GetStoreRoleOfUser(user.Id);
        var isStoreOwner = role != null && role.Permissions.Contains(Policies.CanModifyStoreSettings);
        var isActiveUser = !await userManager.IsLockedOutAsync(user);
        return isStoreOwner && isActiveUser && accessTokenMatches ? $"{login}:{password}" : null;
    }

    public async Task<bool> HasAccess(string storeId, string token)
    {
        var isValid = TryParseToken(token, out var userId, out var password);

        return isValid && await AccessToken(storeId, userId, password) == token;
    }

    public bool TryParseToken(string token, out string? userId, out string? accessKey)
    {
        var parts = string.IsNullOrEmpty(token) ? null : token.Split(':');
        userId = parts is { Length: 2 } ? parts[0] : null;
        accessKey = parts is { Length: 2 } ? parts[1] : null;

        return userId != null && accessKey != null;
    }
}
