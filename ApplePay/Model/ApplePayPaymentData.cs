using Newtonsoft.Json;

namespace ApplePay.Model
{
    public class ApplePayPaymentData
    {
        [JsonProperty("version")]
        public string Version { get; set; }

        [JsonProperty("data")]
        public string Data { get; set; }

        [JsonProperty("signature")]
        public string Signature { get; set; }

        [JsonProperty("header")]
        public ApplePayPaymentDataHeader Header { get; set; }
    }
}
