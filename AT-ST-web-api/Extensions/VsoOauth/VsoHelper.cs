


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
using Microsoft.AspNetCore.Http;

namespace Extensions.VsoOauth
{
    public class VsoOAuthHelper
    {
        private readonly VsoOAuthSettings _oauthVsoSettings;

        public VsoOAuthHelper(VsoOAuthSettings oauthVsoSettings)
        {
            _oauthVsoSettings = oauthVsoSettings;
        }
        public string PerformTokenRequest(string postData, out VsoOauthToken token)
        {
            var error = string.Empty;
            var strResponseData = string.Empty;

            // var tokenEndpoint = Configuration.GetValue<string>("oauth:vso:TokenEndpoint");

            var tokenEndpoint = _oauthVsoSettings.TokenEndpoint;

            HttpWebRequest webRequest = (HttpWebRequest)WebRequest.Create(tokenEndpoint);

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

                    token = JsonConvert.DeserializeObject<VsoOauthToken>(strResponseData);
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

            token = new VsoOauthToken();
            return error;
        }

        public string GenerateAuthorizeUrl(HttpRequest request)
        {
            string providerClientId = _oauthVsoSettings.ClientId;
            string providerScope = _oauthVsoSettings.Scope;
            string authorizationEndpoint = _oauthVsoSettings.AuthorizationEndpoint;
            string providerCallbackEndpoint = _oauthVsoSettings.CallbackEndpoint;

            var redirect_uri = new UriBuilder(request.Scheme, request.Host.Host);
            if (request.Host.Port.HasValue) {
                redirect_uri.Port = request.Host.Port.Value;
            }
            redirect_uri.Path = providerCallbackEndpoint;

            UriBuilder uriBuilder = new UriBuilder(authorizationEndpoint);
            var queryParams = HttpUtility.ParseQueryString(uriBuilder.Query ?? string.Empty);
    
            queryParams["client_id"] = providerClientId;
            queryParams["response_type"] = "Assertion";
            queryParams["state"] = "state";
            queryParams["scope"] = providerScope;
            queryParams["redirect_uri"] = redirect_uri.ToString();

            uriBuilder.Query = queryParams.ToString();

            return uriBuilder.ToString();
        }

        public string GenerateRequestPostData(HttpRequest request, string code)
        {
            var providerClientSecret = _oauthVsoSettings.ClientSecret;
            var providerCallbackEndpoint = _oauthVsoSettings.CallbackEndpoint;

            var redirect_uri = new UriBuilder(request.Scheme, request.Host.Host);
            if (request.Host.Port.HasValue) {
                redirect_uri.Port = request.Host.Port.Value;
            }
            redirect_uri.Path = providerCallbackEndpoint;

            return string.Format("client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer&client_assertion={0}&grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion={1}&redirect_uri={2}",
                HttpUtility.UrlEncode(providerClientSecret),
                HttpUtility.UrlEncode(code),
                redirect_uri.ToString()
                );
        }

        public string GenerateRefreshPostData(HttpRequest request, string refreshToken)
        {
            var providerClientSecret = _oauthVsoSettings.ClientSecret;
            var providerCallbackEndpoint = _oauthVsoSettings.CallbackEndpoint;

            var redirect_uri = new UriBuilder(request.Scheme, request.Host.Host);
            if (request.Host.Port.HasValue) {
                redirect_uri.Port = request.Host.Port.Value;
            }
            redirect_uri.Path = providerCallbackEndpoint;

            return string.Format("client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer&client_assertion={0}&grant_type=refresh_token&assertion={1}&redirect_uri={2}",
                HttpUtility.UrlEncode(providerClientSecret),
                HttpUtility.UrlEncode(refreshToken),
                redirect_uri.ToString()
                );

        }
    }
}