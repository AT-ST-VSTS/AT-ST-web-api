using System;
using Newtonsoft.Json;

namespace Extensions.VsoOauth
{
    public class VsoOauthToken
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

    public class VsoOAuthSettings
    {
        public string ClientId { get; set; }

        public string ClientSecret { get; set; }

        public string Scope { get; set; }

        public string TokenEndpoint { get; set; }
        
        public string AuthorizationEndpoint { get; set; }

        public string CallbackEndpoint { get; set; }
    }
}