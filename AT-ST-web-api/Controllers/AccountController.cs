
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

namespace AT_ST_web_api.Controllers
{

    [Route("[controller]")]
    public class AccountController : Controller
    {
        
        private readonly OAuthSettings _oauthSettings;
    
        public AccountController(IOptions<OAuthSettings> oauthSettings)
        {
            _oauthSettings = oauthSettings.Value;
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

        [HttpGet("login")]
        public IActionResult Login(string returnUrl = "/")
        {   
            return Challenge(new AuthenticationProperties() { RedirectUri = returnUrl });
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
