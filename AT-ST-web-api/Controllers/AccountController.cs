
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Web;
using Newtonsoft.Json;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using AT_ST_web_api.Models;
using Extensions.VsoOauth;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Authorization;
using System.Threading.Tasks;

namespace AT_ST_web_api.Controllers
{

    [Route("[controller]")]
    public class AccountController : Controller
    {
        
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly OAuthSettings _oauthSettings;
    
        public AccountController(
            IOptions<OAuthSettings> oauthSettings,
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager)
        {
            _oauthSettings = oauthSettings.Value;
            _signInManager = signInManager;
            _userManager = userManager;
         }

        [HttpGet]
        public IActionResult Profile()
        {
            if (!User.Identity.IsAuthenticated)
            {
                throw new UnauthorizedAccessException();
            }

            return new JsonResult(User.Claims);
        }









        [HttpGet("login")] // or HttpPost
        [AllowAnonymous]
        public IActionResult Login(string provider, string returnUrl = null)
        {
            // Request a redirect to the external login provider.
            var redirectUrl = Url.Action("ExternalLoginCallback", "Account", new { returnUrl });
            var properties = _signInManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl);
            return Challenge(properties, provider);
        }


        [TempData]
        public string ErrorMessage { get; set; }


        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> ExternalLoginCallback(string returnUrl = null, string remoteError = null)
        {
            if (remoteError != null)
            {
                throw new Exception($"Error from external provider: {remoteError}");
            }
            var info = await _signInManager.GetExternalLoginInfoAsync();
            if (info == null)
            {
                throw new Exception("info == null");
                // return RedirectToAction(nameof(Login));
            }

            // Sign in the user with this external login provider if the user already has a login.
            var result = await _signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, isPersistent: false, bypassTwoFactor: true);
            if (result.Succeeded)
            {
                var user = await _userManager.GetUserAsync(User);
                return new JsonResult( new { user = user, AuthenticationTokens = info.AuthenticationTokens });
                // _logger.LogInformation("User logged in with {Name} provider.", info.LoginProvider);
                // return Redirect(returnUrl);
            }
            if (result.IsNotAllowed)
            {
                return new JsonResult( new { IsNotAllowed = true });
                // return RedirectToAction(nameof(Lockout));
            }
            if (result.IsLockedOut)
            {
                return new JsonResult( new { IsLockedOut = true });
                // return RedirectToAction(nameof(Lockout));
            }
            else
            {
                // If the user does not have an account, then ask the user to create an account.
                // ViewData["ReturnUrl"] = returnUrl;
                // ViewData["LoginProvider"] = info.LoginProvider;
                // var email = info.Principal.FindFirstValue(ClaimTypes.Email);
                // return View("ExternalLogin", new ExternalLoginViewModel { Email = email });

                var user = new ApplicationUser { UserName = "aaaaaaaaa" };
                var resultCreate = await _userManager.CreateAsync(user);
                if (resultCreate.Succeeded)
                {
                    resultCreate = await _userManager.AddLoginAsync(user, info);
                    if (resultCreate.Succeeded)
                    {
                        await _signInManager.SignInAsync(user, isPersistent: false);

                        return new JsonResult( new { user = user, AuthenticationTokens = info.AuthenticationTokens });
                        // _logger.LogInformation("User created an account using {Name} provider.", info.LoginProvider);
                        //return RedirectToLocal(returnUrl);
                    }
                }
                throw new Exception("failed creating user");
            }
        }






        [HttpGet("oauth-login")]
        public IActionResult OAuthLogin()
        {   
            var oauthVsoHelper = new VsoOAuthHelper(_oauthSettings.OAuthVsoSettings);
            string url = oauthVsoHelper.GenerateAuthorizeUrl(Request);
            return new RedirectResult(url);
        }

        [HttpGet("oauth-callback")]
        public ActionResult OAuthCallback(string code, string state, string error)
        {
            if(!string.IsNullOrEmpty(error)) {
                throw new Exception(error);
            }

            VsoOauthToken token = new VsoOauthToken();
            string tokenError = null;

            if (!string.IsNullOrEmpty(code))
            {
                var oauthVsoHelper = new VsoOAuthHelper(_oauthSettings.OAuthVsoSettings);
                var postData = oauthVsoHelper.GenerateRequestPostData(Request, code);
                tokenError = oauthVsoHelper.PerformTokenRequest(postData, out token);
                if (string.IsNullOrEmpty(tokenError))
                {
                    ViewBag.Token = token;
                }
            }

            ViewBag.Error = tokenError;

            return View("TokenView");
        }

        [HttpGet("oauth-RefreshToken")]
        public ActionResult OAuthRefreshToken(string refreshToken)
        {
            VsoOauthToken token = new VsoOauthToken();
            string error = null;

            if (!string.IsNullOrEmpty(refreshToken))
            {
                var oauthVsoHelper = new VsoOAuthHelper(_oauthSettings.OAuthVsoSettings);
                var postData = oauthVsoHelper.GenerateRefreshPostData(Request, refreshToken);
                error = oauthVsoHelper.PerformTokenRequest(postData, out token);
                if (string.IsNullOrEmpty(error))
                {
                    ViewBag.Token = token;
                }
            }

            ViewBag.Error = error;

            return View("TokenView");
        }



    }
}
