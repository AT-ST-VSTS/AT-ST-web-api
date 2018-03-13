using System;
using Newtonsoft.Json;

namespace AT_ST_web_api.Models
{
    public class OAuthSettings
    {
        public VisualStudioOAuthSettings OAuthVsoSettings { get; set; }
    }

    public class VisualStudioOauthToken
    {
        [JsonProperty(PropertyName = "access_token")]
        public string accessToken { get; set; }

        [JsonProperty(PropertyName = "token_type")]
        public string tokenType { get; set; }

        [JsonProperty(PropertyName = "expires_in")]
        public string expiresIn { get; set; }

        [JsonProperty(PropertyName = "refresh_token")]
        public string refreshToken { get; set; }

    }

    public class VisualStudioOAuthSettings
    {
        public string ClientId { get; set; }

        public string ClientSecret { get; set; }

        public string Scope { get; set; }
    }
}