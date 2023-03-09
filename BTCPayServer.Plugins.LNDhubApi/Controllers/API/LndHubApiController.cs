using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using BTCPayServer.Abstractions.Contracts;
using BTCPayServer.Client;
using BTCPayServer.Client.Models;
using BTCPayServer.Data;
using BTCPayServer.Lightning;
using BTCPayServer.Lightning.LNDhub.Models;
using BTCPayServer.Payments;
using BTCPayServer.Payments.Lightning;
using BTCPayServer.Plugins.LNDhubApi.Authentication;
using BTCPayServer.Security;
using BTCPayServer.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Cors;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.Options;
using NBitcoin;
using CreateInvoiceRequest = BTCPayServer.Lightning.LNDhub.Models.CreateInvoiceRequest;
using InvoiceData = BTCPayServer.Lightning.LNDhub.Models.InvoiceData;
using PaymentData = BTCPayServer.Lightning.LNDhub.Models.PaymentData;

namespace BTCPayServer.Plugins.LNDhubApi.Controllers.API;

public class LNDhubApiExceptionFilter : Attribute, IExceptionFilter
{
    public void OnException(ExceptionContext context)
    {
        context.Result = new ObjectResult(new ErrorResponse(6, context.Exception.Message)) { StatusCode = 503 };
        context.ExceptionHandled = true;
    }
}

[ApiController]
[Authorize(AuthenticationSchemes = LNDhubApiAuthenticationSchemes.AccessKey)]
[LNDhubApiExceptionFilter]
[EnableCors(CorsPolicies.All)]
[Route("~/plugins/lndhub-api/{storeId}/api")]
public class LndHubApiController : ControllerBase
{
    private const string CryptoCode = "BTC";
    private readonly IOptionsMonitor<IdentityOptions> _identityOptions;
    private readonly BTCPayNetworkProvider _networkProvider;
    private readonly IBTCPayServerClientFactory _clientFactory;
    private readonly LNDhubApiAuthenticator _authenticator;
    private readonly PoliciesSettings _policiesSettings;

    public LndHubApiController(
        IOptionsMonitor<IdentityOptions> identityOptions,
        BTCPayNetworkProvider networkProvider,
        IBTCPayServerClientFactory clientFactory,
        LNDhubApiAuthenticator authenticator,
        PoliciesSettings policiesSettings)
    {
        _networkProvider = networkProvider;
        _identityOptions = identityOptions;
        _clientFactory = clientFactory;
        _authenticator = authenticator;
        _policiesSettings = policiesSettings;
    }

    // https://github.com/BlueWallet/LndHub/blob/master/doc/Send-requirements.md#post-authtypeauth
    [AllowAnonymous]
    [HttpPost("auth")]
    public async Task<IActionResult> Auth(string storeId, AuthRequest req, [FromQuery] string type)
    {
        AuthResponse result = null;
        switch (type)
        {
            case "auth":
                var accessToken = await _authenticator.AccessToken(storeId, req.Login, req.Password);
                result = new AuthResponse { AccessToken = accessToken, RefreshToken = accessToken };
                break;

            // fake this case as we don't do OAuth
            case "refresh_token":
                result = new AuthResponse { AccessToken = req.RefreshToken, RefreshToken = req.RefreshToken };
                break;
        }

        return Ok(string.IsNullOrEmpty(result?.AccessToken) ? new ErrorResponse(1) : result);
    }

    // https://github.com/BlueWallet/LndHub/blob/master/doc/Send-requirements.md#get-getinfo
    [HttpGet("getinfo")]
    public async Task<IActionResult> Info(string storeId, CancellationToken cancellationToken = default)
    {
        var store = HttpContext.GetStoreData();
        var client = await Client();
        var info = await client.GetLightningNodeInfo(storeId, CryptoCode, cancellationToken);
        var result = new NodeInfoData
        {
            Uris = info.NodeURIs.Select(uri => uri.ToString()),
            IdentityPubkey = info.NodeURIs.First().NodeId.ToString(),
            BlockHeight = info.BlockHeight,
            Alias = store.StoreName,
            Color = info.Color,
            Version = info.Version,
            PeersCount = info.PeersCount.HasValue ? Convert.ToInt32(info.PeersCount.Value) : 0,
            ActiveChannelsCount = info.ActiveChannelsCount.HasValue ? Convert.ToInt32(info.ActiveChannelsCount.Value) : 0,
            InactiveChannelsCount = info.InactiveChannelsCount.HasValue ? Convert.ToInt32(info.InactiveChannelsCount.Value) : 0,
            PendingChannelsCount = info.PendingChannelsCount.HasValue ? Convert.ToInt32(info.PendingChannelsCount.Value) : 0
        };
        return Ok(result);
    }

    // https://github.com/BlueWallet/LndHub/blob/master/doc/Send-requirements.md#get-getpending
    [HttpGet("getpending")]
    public IActionResult PendingTransactions(string storeId, CancellationToken cancellationToken = default)
    {
        // There are no pending BTC transactions, so leave it as an empty implementation
        return Ok(new List<TransactionData>());
    }

    // https://github.com/BlueWallet/LndHub/blob/master/doc/Send-requirements.md#get-gettxs
    [HttpGet("gettxs")]
    public async Task<IActionResult> Transactions(string storeId, [FromQuery] int? limit, [FromQuery] int? offset, CancellationToken cancellationToken = default)
    {
        var network = _networkProvider.GetNetwork<BTCPayNetwork>(CryptoCode);
        var client = await Client();
        var payments = await client.GetLightningPayments(storeId, CryptoCode, false, offset, cancellationToken);
        var transactions = payments?.Select(p => ToTransactionData(p, network))
            ?? new List<TransactionData>();
        return Ok(transactions);
    }

    // https://github.com/BlueWallet/LndHub/blob/master/doc/Send-requirements.md#get-getuserinvoices
    [HttpGet("getuserinvoices")]
    public async Task<IActionResult> UserInvoices(string storeId, CancellationToken cancellationToken = default)
    {
        var network = _networkProvider.GetNetwork<BTCPayNetwork>(CryptoCode);
        var client = await Client();
        var invoices = await client.GetLightningInvoices(storeId, CryptoCode, false, null, cancellationToken);
        var userInvoices = invoices?.Select(i =>
        {
            var bolt11 = BOLT11PaymentRequest.Parse(i.BOLT11, network.NBitcoinNetwork);
            return ToInvoiceData(i, bolt11);
        }) ?? new List<InvoiceData>();;
        return Ok(userInvoices);
    }

    // https://github.com/BlueWallet/LndHub/blob/master/doc/Send-requirements.md#get-getbalance
    [HttpGet("balance")]
    public async Task<IActionResult> Balance(string storeId, CancellationToken cancellationToken = default)
    {
        var client = await Client();
        var balance = await client.GetLightningNodeBalance(storeId, CryptoCode, cancellationToken);
        var btc = new BtcBalance { AvailableBalance = balance.OffchainBalance?.Local };
        var result = new BalanceData { BTC = btc };

        return Ok(result);
    }

    // https://github.com/BlueWallet/LndHub/blob/master/doc/Send-requirements.md#get-decodeinvoice
    [HttpGet("decodeinvoice")]
    public IActionResult DecodeInvoice(string storeId, [FromQuery] string invoice, CancellationToken cancellationToken = default)
    {
        var network = _networkProvider.GetNetwork<BTCPayNetwork>(CryptoCode);
        try
        {
            var bolt11 = BOLT11PaymentRequest.Parse(invoice, network.NBitcoinNetwork);
            var decoded = new DecodeInvoiceData
            {
                Destination = bolt11.GetPayeePubKey().ToString(),
                PaymentHash = bolt11.PaymentHash?.ToString(),
                Amount = bolt11.MinimumAmount,
                Timestamp = bolt11.Timestamp,
                Expiry = bolt11.ExpiryDate - bolt11.Timestamp,
                Description = bolt11.ShortDescription,
                DescriptionHash = bolt11.DescriptionHash
            };

            return Ok(decoded);
        }
        catch (Exception ex)
        {
            return Ok(new ErrorResponse(4, ex.Message));
        }
    }

    // https://github.com/getAlby/lightning-browser-extension/blob/f0b0ab9ad0b2dd6e60b864548fa39091ef81bbdc/src/extension/background-script/connectors/lndhub.ts#L249
    [HttpGet("checkpayment/{paymentHash}")]
    public async Task<IActionResult> CheckPayment(string storeId, string paymentHash, CancellationToken cancellationToken = default)
    {
        var client = await Client();
        var result = new CheckPaymentResponse { Paid = false };
        try
        {
            var payment = await client.GetLightningPayment(storeId, CryptoCode, paymentHash, cancellationToken);
            result.Paid = payment.Status == LightningPaymentStatus.Complete;
            return Ok(result);
        }
        catch (Exception)
        {
            return NotFound(result);
        }
    }

    // https://github.com/BlueWallet/LndHub/blob/master/doc/Send-requirements.md#post-addinvoice
    [HttpPost("addinvoice")]
    public async Task<IActionResult> AddInvoice(string storeId, CreateInvoiceRequest request, CancellationToken cancellationToken = default)
    {
        var network = _networkProvider.GetNetwork<BTCPayNetwork>(CryptoCode);
        var client = await Client();
        if (request.Amount < LightMoney.Zero)
        {
            return Ok(new ErrorResponse(4, "Amount should be more or equals to 0"));
        }
        try
        {
            var descHashOnly = request.DescriptionHash is not null;
            var desc = descHashOnly ? request.DescriptionHash.ToString() : request.Memo;
            var  req = new CreateLightningInvoiceRequest
            {
                Amount = request.Amount,
                Description = desc,
                DescriptionHashOnly = descHashOnly,
                Expiry = TimeSpan.FromDays(1),
                PrivateRouteHints = true
            };
            var invoice = await client.CreateLightningInvoice(storeId, CryptoCode, req, cancellationToken);
            var bolt11 = BOLT11PaymentRequest.Parse(invoice.BOLT11, network.NBitcoinNetwork);
            var res = ToInvoiceData(invoice, bolt11);

            return Ok(res);
        }
        catch (Exception ex)
        {
            return Ok(new ErrorResponse(4, ex.Message));
        }
    }

    // https://github.com/BlueWallet/LndHub/blob/master/doc/Send-requirements.md#post-payinvoice
    [HttpPost("payinvoice")]
    public async Task<IActionResult> PayInvoice(string storeId, PayInvoiceRequest request, CancellationToken cancellationToken = default)
    {
        var client = await Client();
        var network = _networkProvider.GetNetwork<BTCPayNetwork>(CryptoCode);

        if (string.IsNullOrEmpty(request.PaymentRequest) ||
            !BOLT11PaymentRequest.TryParse(request.PaymentRequest, out var bolt11, network.NBitcoinNetwork))
        {
            return Ok(new ErrorResponse(4, "The BOLT11 invoice was invalid."));
        }

        try
        {
            var amount = bolt11?.MinimumAmount is null ? request.Amount : null;
            var req = new PayLightningInvoiceRequest
            {
                BOLT11 = request.PaymentRequest,
                Amount = amount
            };
            var payment = await client.PayLightningInvoice(storeId, CryptoCode, req, cancellationToken);
            var res = ToPaymentResponse(payment, bolt11);

            return Ok(res);
        }
        catch (Exception ex)
        {
            return Ok(new ErrorResponse(4, ex.Message));
        }
    }

    /* TODO: We could implement this endpoint too
    //https://github.com/BlueWallet/LndHub/blob/master/doc/Send-requirements.md#get-getbtc
    [Authorize(Policy = Policies.CanUseLightningNodeInStore, AuthenticationSchemes = AuthenticationSchemes.Greenfield)]
    [HttpPost("~/api/v1/stores/{storeId}/lightning/{cryptoCode}/address")]
    public override Task<IActionResult> GetDepositAddress(string cryptoCode, CancellationToken cancellationToken = default)
    {
        return base.GetDepositAddress(cryptoCode, cancellationToken);
    }
    */

    private InvoiceData ToInvoiceData(LightningInvoiceData t, BOLT11PaymentRequest bolt11)
    {
        var expireTime = TimeSpan.FromSeconds((bolt11.ExpiryDate - DateTime.Now).TotalSeconds);
        return new InvoiceData
        {
            Id = bolt11.Hash,
            Description = bolt11.ShortDescription,
            AddIndex = Convert.ToInt32(t.PaidAt?.ToUnixTimeSeconds()), // fake it
            PaymentHash = bolt11.PaymentHash?.ToString(),
            PaymentRequest = t.BOLT11,
            IsPaid = t.Status == LightningInvoiceStatus.Paid,
            ExpireTime = expireTime,
            Amount = t.Amount,
            CreatedAt = bolt11.Timestamp
        };
    }

    private TransactionData ToTransactionData(LightningPaymentData t, BTCPayNetwork network)
    {
        var bolt11 = BOLT11PaymentRequest.Parse(t.BOLT11, network.NBitcoinNetwork);
        return new TransactionData
        {
            PaymentHash = string.IsNullOrEmpty(t.PaymentHash) ? null : uint256.Parse(t.PaymentHash),
            PaymentPreimage = t.Preimage,
            Fee = t.FeeAmount,
            Value = t.TotalAmount,
            Timestamp = t.CreatedAt,
            Memo = bolt11.ShortDescription
        };
    }

    private PaymentResponse ToPaymentResponse(LightningPaymentData t, BOLT11PaymentRequest bolt11)
    {
        var error = t.Status switch
        {
            LightningPaymentStatus.Failed => "Payment failed",
            LightningPaymentStatus.Pending => "Payment pending",
            LightningPaymentStatus.Unknown => "Payment status unknown",
            _ => "" // needs to be an empty string for compatibility across wallets
        };
        var expireTime = TimeSpan.FromSeconds((bolt11.ExpiryDate - DateTime.Now).TotalSeconds);
        var preimage = string.IsNullOrEmpty(t.Preimage) ? null : uint256.Parse(t.Preimage);
        var paymentHash = string.IsNullOrEmpty(t.PaymentHash) ? null : uint256.Parse(t.PaymentHash);
        return new PaymentResponse
        {
            PaymentError = error,
            PaymentRequest = bolt11.ToString(),
            PaymentPreimage = preimage,
            PaymentHash = paymentHash,
            Decoded = new PaymentData
            {
                PaymentPreimage = preimage,
                PaymentHash = paymentHash,
                Destination = bolt11.GetPayeePubKey().ToString(),
                Amount = t.TotalAmount,
                Description = bolt11.ShortDescription,
                DescriptionHash = bolt11.DescriptionHash?.ToString(),
                ExpireTime = expireTime,
                Timestamp = bolt11.Timestamp
            },
            PaymentRoute = new PaymentRoute
            {
                Amount = t.TotalAmount,
                Fee = t.FeeAmount
            }
        };
    }

    private async Task<BTCPayServerClient> Client()
    {
        var userId = User.Claims.First(c => c.Type == _identityOptions.CurrentValue.ClaimsIdentity.UserIdClaimType).Value;
        var storeId = User.Claims.First(c => c.Type == LNDhubApiClaimTypes.StoreId).Value;
        var store = HttpContext.GetStoreData();

        // Check that Lightning is enabled
        var lnId = new PaymentMethodId(CryptoCode, PaymentTypes.LightningLike);
        var lightning = store
            .GetSupportedPaymentMethods(_networkProvider)
            .OfType<LightningSupportedPaymentMethod>()
            .FirstOrDefault(m => m.PaymentId == lnId);
        var excludeFilters = store.GetStoreBlob().GetExcludedPaymentMethods();
        var isEnabled = lightning != null && !excludeFilters.Match(lightning.PaymentId);
        if (!isEnabled)
            throw new Exception("The store's Lightning node is not set up");

        var canUseInternal = User.IsInRole(Roles.ServerAdmin) || _policiesSettings.AllowLightningInternalNodeForAll;
        if (lightning.IsInternalNode && !canUseInternal)
            throw new Exception("The internal Lightning node can only be used by admins");

        return await _clientFactory.Create(userId, new [] { storeId }, HttpContext);
    }
}
