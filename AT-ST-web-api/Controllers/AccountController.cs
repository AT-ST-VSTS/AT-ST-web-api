
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
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using OAuth.Models;

namespace AT_ST_web_api.Controllers
{

    [Produces("application/json")]
    [Route("[controller]/[action]")]
    public class AccountController : Controller
    {
        public IConfiguration Configuration { get; private set; }
    
        public AccountController(IConfiguration settings)
        {
            this.Configuration = settings;
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
        public IActionResult Config()
        {
            return new JsonResult(this.Configuration["oauth:vso:AuthorizationEndpoint"]);
        }









        [HttpGet]
        public IActionResult LoginOAuth(string provider = "vso")
        {
            return new RedirectResult(GenerateAuthorizeUrl(provider));
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

        private String GenerateAuthorizeUrl(string provider = "vso")
        {
            var providerConfiguration = this.Configuration.GetSection("oauth:"+ provider);

            var authorizationEndpoint = providerConfiguration["AuthorizationEndpoint"];
            var providerClientId = providerConfiguration["ClientId"];
            var providerScope = providerConfiguration["Scope"];
            var providerCallbackEndpoint = providerConfiguration["CallbackEndpoint"];

            var redirect_uri = new UriBuilder(Request.Scheme, Request.Host.Host, Request.Host.Port.Value, providerCallbackEndpoint).ToString();

            UriBuilder uriBuilder = new UriBuilder(authorizationEndpoint);
            var queryParams = HttpUtility.ParseQueryString(uriBuilder.Query ?? String.Empty);
    
            queryParams["client_id"] = providerClientId;
            queryParams["response_type"] = "Assertion";
            queryParams["state"] = "state";
            queryParams["scope"] = providerScope;
            queryParams["redirect_uri"] = redirect_uri;

            uriBuilder.Query = queryParams.ToString();

            return uriBuilder.ToString();
        }

        private string GenerateRequestPostData(string code, string provider = "vso")
        {
            var providerConfiguration = this.Configuration.GetSection("oauth:"+ provider);

            var providerClientSecret = providerConfiguration["ClientSecret"];
            var providerCallbackEndpoint = providerConfiguration["CallbackEndpoint"];

            var redirect_uri = new UriBuilder(Request.Scheme, Request.Host.Value, Request.Host.Port.Value, providerCallbackEndpoint).ToString();

            return string.Format("client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer&client_assertion={0}&grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion={1}&redirect_uri={2}",
                HttpUtility.UrlEncode(providerClientSecret),
                HttpUtility.UrlEncode(code),
                redirect_uri
                );
        }

        private string GenerateRefreshPostData(string refreshToken, string provider = "vso")
        {
            var providerConfiguration = this.Configuration.GetSection("oauth:"+ provider);

            var providerClientSecret = providerConfiguration["ClientSecret"];
            var providerCallbackEndpoint = providerConfiguration["CallbackEndpoint"];

            var redirect_uri = new UriBuilder(Request.Scheme, Request.Host.Value, Request.Host.Port.Value, providerCallbackEndpoint).ToString();

            return string.Format("client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer&client_assertion={0}&grant_type=refresh_token&assertion={1}&redirect_uri={2}",
                HttpUtility.UrlEncode(providerClientSecret),
                HttpUtility.UrlEncode(refreshToken),
                redirect_uri
                );

        }
    }
}
