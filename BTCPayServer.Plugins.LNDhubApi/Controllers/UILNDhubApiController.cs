using System;
using System.Threading.Tasks;
using BTCPayServer.Abstractions.Constants;
using BTCPayServer.Abstractions.Contracts;
using BTCPayServer.Client;
using BTCPayServer.Data;
using BTCPayServer.Plugins.LNDhubApi.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using NBitcoin;
using NBitcoin.DataEncoders;

namespace BTCPayServer.Plugins.LNDhubApi.Controllers;

[Route("~/plugins/lndhub-api/{storeId}")]
[Authorize(AuthenticationSchemes = AuthenticationSchemes.Cookie, Policy = Policies.CanViewProfile)]
public class UILNDhubApiController(
    UserManager<ApplicationUser> userManager,
    IStoreRepository storeRepository)
    : Controller
{
    [HttpGet]
    public async Task<IActionResult> Index(string storeId)
    {
        var settings = await storeRepository.GetSettingAsync<LNDhubApiSettings>(storeId, LNDhubApiPlugin.SettingsKey) ?? new LNDhubApiSettings();
        var vm = new IndexViewModel { Settings = settings };
        if (settings is { Enabled: true })
        {
            var userId = userManager.GetUserId(User);
            var req = HttpContext.Request;
            var baseUrl = $"{req.Scheme}://{req.Host}{req.PathBase.ToUriComponent()}";
            var endpoint = new Uri($"{baseUrl}/plugins/lndhub-api/{storeId}/api/");
            vm.AccessUrl = $"lndhub://{userId}:{settings.AccessToken}@{endpoint}";
        }

        return View(vm);
    }

    [HttpPost]
    public async Task<IActionResult> Update(string storeId, bool? enabled, bool? regenerate)
    {
        var settings = await GetSetting(storeId);
        if (enabled.HasValue)
            settings.Enabled = enabled.Value;
        if ((settings.Enabled && string.IsNullOrEmpty(settings.AccessToken)) || (regenerate.HasValue && regenerate.Value))
            settings.AccessToken = Encoders.Hex.EncodeData(RandomUtils.GetBytes(21));
        await storeRepository.UpdateSetting(storeId, LNDhubApiPlugin.SettingsKey, settings);
        TempData[WellKnownTempData.SuccessMessage] = $"LNDhub API {(settings.Enabled ? "enabled" : "disabled")}";
        return RedirectToAction(nameof(Index), new { storeId });
    }

    private async Task<LNDhubApiSettings> GetSetting(string storeId)
    {
        return await storeRepository.GetSettingAsync<LNDhubApiSettings>(storeId, LNDhubApiPlugin.SettingsKey) ??
               new LNDhubApiSettings();
    }
}
