using BTCPayServer.Abstractions.Contracts;
using BTCPayServer.Abstractions.Models;
using BTCPayServer.Abstractions.Services;
using BTCPayServer.Plugins.LNDhubApi.Authentication;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;

namespace BTCPayServer.Plugins.LNDhubApi;

public class LNDhubApiPlugin : BaseBTCPayServerPlugin
{
    internal const string SettingsKey = "lndhub-api";

    public override IBTCPayServerPlugin.PluginDependency[] Dependencies { get; } =
    {
        new () { Identifier = nameof(BTCPayServer), Condition = ">=1.12.0" }
    };

    public override void Execute(IServiceCollection services)
    {
        services.AddSingleton<IUIExtension>(new UIExtension("LNDhubApiNavExtension", "header-nav"));

        services.AddSingleton<LNDhubApiAuthenticator>();

        var builder = new AuthenticationBuilder(services);
        builder.AddScheme<LNDhubApiAuthenticationOptions, LNDhubApiAuthenticationHandler>(LNDhubApiAuthenticationSchemes.AccessKey,
            _ => { });
    }
}
