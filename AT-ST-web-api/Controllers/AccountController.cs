
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using System.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using OAuthSample.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;

namespace AT_ST_web_api.Controllers
{

    [Produces("application/json")]
    [Route("[controller]/[action]")]
    public class AccountController : Controller
    {
        private IConfiguration Configuration;
 
        public AccountController(IConfiguration configuration)
        {
            this.Configuration = configuration;
        }

        [HttpGet]
        public IActionResult Login(string returnUrl = "/")
        {
            return Challenge(new AuthenticationProperties() { RedirectUri = returnUrl });
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











        [HttpGet]
        public ActionResult RequestToken(string code, string status)
        {
            return new RedirectResult(GenerateAuthorizeUrl());
        }

        [HttpGet]
        public ActionResult RefreshToken(string refreshToken)
        {
            TokenModel token = new TokenModel();
            String error = null;

            if (!String.IsNullOrEmpty(refreshToken))
            {
                error = PerformTokenRequest(GenerateRefreshPostData(refreshToken), out token);
                if (String.IsNullOrEmpty(error))
                {
                    ViewBag.Token = token;
                }
            }

            ViewBag.Error = error;

            return View("TokenView");
        }

        [HttpGet]
        public ActionResult Callback(string code, string state)
        {
            TokenModel token = new TokenModel();
            String error = null;

            if (!String.IsNullOrEmpty(code))
            {
                error = PerformTokenRequest(GenerateRequestPostData(code), out token);
                if (String.IsNullOrEmpty(error))
                {
                    ViewBag.Token = token;
                }
            }

            ViewBag.Error = error;

            return View("TokenView");
        }

        private String PerformTokenRequest(String postData, out TokenModel token)
        {
            var error = String.Empty;
            var strResponseData = String.Empty;

            HttpWebRequest webRequest = (HttpWebRequest)WebRequest.Create(
                this.Configuration["oauth:vso:TokenEndpoint"]
            );

            webRequest.Method = "POST";
            webRequest.ContentLength = postData.Length;
            webRequest.ContentType = "application/x-www-form-urlencoded";

            using (StreamWriter swRequestWriter = new StreamWriter(webRequest.GetRequestStream()))
            {
                swRequestWriter.Write(postData);
            }

            try
            {
                HttpWebResponse hwrWebResponse = (HttpWebResponse)webRequest.GetResponse();

                if (hwrWebResponse.StatusCode == HttpStatusCode.OK)
                {
                    using (StreamReader srResponseReader = new StreamReader(hwrWebResponse.GetResponseStream()))
                    {
                        strResponseData = srResponseReader.ReadToEnd();
                    }

                    token = JsonConvert.DeserializeObject<TokenModel>(strResponseData);
                    return null;
                }
            }
            catch (WebException wex)
            {
                error = "Request Issue: " + wex.Message;
            }
            catch (Exception ex)
            {
                error = "Issue: " + ex.Message;
            }

            token = new TokenModel();
            return error;
        }

        private String GenerateAuthorizeUrl()
        {
            UriBuilder uriBuilder = new UriBuilder(this.Configuration["oauth:vso:AuthorizationEndpoint"]);
            var queryParams = HttpUtility.ParseQueryString(uriBuilder.Query ?? String.Empty);

            queryParams["client_id"] = this.Configuration["oauth:vso:ClientId"];
            queryParams["response_type"] = "Assertion";
            queryParams["state"] = "state";
            queryParams["scope"] = this.Configuration["oauth:vso:Scope"];
            queryParams["redirect_uri"] = new PathString(this.Configuration["oauth:vso:CallbackEndpoint"]);
    
            uriBuilder.Query = queryParams.ToString();

            return uriBuilder.ToString();
        }

        private string GenerateRequestPostData(string code)
        {
            return string.Format("client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer&client_assertion={0}&grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion={1}&redirect_uri={2}",
                HttpUtility.UrlEncode(this.Configuration["oauth:vso:ClientSecret"]),
                HttpUtility.UrlEncode(code),
                this.Configuration["oauth:vso:CallbackEndpoint"]
                );
        }

        private string GenerateRefreshPostData(string refreshToken)
        {
            return string.Format("client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer&client_assertion={0}&grant_type=refresh_token&assertion={1}&redirect_uri={2}",
                HttpUtility.UrlEncode(this.Configuration["ClientSecret"]),
                HttpUtility.UrlEncode(refreshToken),
                this.Configuration["oauth:vso:CallbackEndpoint"]
                );

        }
    }
}


namespace OAuthSample.Models
{
    public class TokenModel
    {
        public TokenModel()
        {

        }

        [JsonProperty(PropertyName = "access_token")]
        public String accessToken { get; set; }

        [JsonProperty(PropertyName = "token_type")]
        public String tokenType { get; set; }

        [JsonProperty(PropertyName = "expires_in")]
        public String expiresIn { get; set; }

        [JsonProperty(PropertyName = "refresh_token")]
        public String refreshToken { get; set; }

    }

}