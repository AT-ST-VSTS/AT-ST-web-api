using System;
using Newtonsoft.Json;
using Extensions.VsoOauth;

namespace AT_ST_web_api.Models
{
    public class OAuthSettings
    {
        public VsoOAuthSettings OAuthVsoSettings { get; set; }
    }
}