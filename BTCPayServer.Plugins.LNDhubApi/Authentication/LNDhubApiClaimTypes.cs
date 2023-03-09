namespace BTCPayServer.Plugins.LNDhubApi.Authentication;

public static class LNDhubApiClaimTypes
{
    private const string ClaimTypeNamespace = "http://btcpayserver.org/plugins/lndhub-api/claims";

    public const string AccessKey = ClaimTypeNamespace + "/accessKey";
    public const string StoreId = ClaimTypeNamespace + "/storeId";
}
