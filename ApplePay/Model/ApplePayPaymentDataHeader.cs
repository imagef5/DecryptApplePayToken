using Newtonsoft.Json;

namespace ApplePay.Model
{
    public class ApplePayPaymentDataHeader
    {
        [JsonProperty("applicationData")]
        public string ApplicationData { get; set; }

        [JsonProperty("ephemeralPublicKey")]
        public string EphemeralPublicKey { get; set; }

        [JsonProperty("wrappedKey")]
        public string WrappedKey { get; set; }

        [JsonProperty("publicKeyHash")]
        public string PublicKeyHash { get; set; }

        [JsonProperty("transactionId")]
        public string TransactionId { get; set; }
    }
}
