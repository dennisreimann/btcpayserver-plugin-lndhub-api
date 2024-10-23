namespace BTCPayServer.Plugins.LNDhubApi.Models;

public class IndexViewModel
{
    public LNDhubApiSettings Settings { get; init; } = null!;
    public string? AccessUrl { get; set; }
}
