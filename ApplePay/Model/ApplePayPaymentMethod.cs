using Newtonsoft.Json;

namespace ApplePay.Model
{
    public class ApplePayPaymentMethod
    {
        [JsonProperty("displayName")]
        public string DisplayName { get; set; }

        [JsonProperty("network")]
        public string Network { get; set; }

        [JsonProperty("type")]
        public string NetworkType { get; set; }
    }
}
