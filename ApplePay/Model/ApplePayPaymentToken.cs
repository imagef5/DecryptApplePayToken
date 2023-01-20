using Newtonsoft.Json;

namespace ApplePay.Model
{
    public class ApplePayPaymentToken
    {
        [JsonProperty("paymentData")]
        public ApplePayPaymentData PaymentData { get; set; }

        [JsonProperty("paymentMethod")]
        public ApplePayPaymentMethod PaymentMethod { get; set; }

        [JsonProperty("transactionIdentifier")]
        public string TransactionIdentifier { get; set; }
    }
}
