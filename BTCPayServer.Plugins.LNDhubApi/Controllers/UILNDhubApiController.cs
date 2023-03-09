using BTCPayServer.Abstractions.Constants;
using BTCPayServer.Client;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace BTCPayServer.Plugins.LNDhubApi.Controllers;

[Route("~/plugins/lndhub-api")]
[Authorize(AuthenticationSchemes = AuthenticationSchemes.Cookie, Policy = Policies.CanViewProfile)]
public class UILNDhubApiController : Controller
{
    public IActionResult Index()
    {
        return View();
    }
}
