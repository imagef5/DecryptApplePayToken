using Newtonsoft.Json;

namespace ApplePay.Model
{
    public class ApplePayDecryptedPaymentData
    {
        [JsonProperty("applicationPrimaryAccountNumber")]
        public string ApplicationPrimaryAccountNumber { get; set; }

        [JsonProperty("applicationExpirationDate")]
        public string ApplicationExpirationDate { get; set; }

        [JsonProperty("currencyCode")]
        public string CurrencyCode { get; set; }

        [JsonProperty("transactionAmount")]
        public int TransactionAmount { get; set; }

        [JsonProperty("cardholderName")]
        public string CardholderName { get; set; }

        [JsonProperty("deviceManufacturerIdentifier")]
        public string DeviceManufacturerIdentifier { get; set; }

        [JsonProperty("paymentDataType")]
        public string PaymentDataType { get; set; }

        [JsonProperty("paymentData")]
        public ApplePayDecryptedPaymentDataDetails PaymentData { get; set; }

        public override string ToString()
        {
            return JsonConvert.SerializeObject(this);
        }
    }
}
