using Newtonsoft.Json;

namespace ApplePay.Model
{
    public class ApplePayDecryptedPaymentDataDetails
    {
        [JsonProperty("onlinePaymentCryptogram")]
        public string OnlinePaymentCryptogram { get; set; }

        [JsonProperty("eciIndicator")]
        public string EciIndicator { get; set; }

        [JsonProperty("emvData")]
        public string EmvData { get; set; }

        [JsonProperty("encryptedPINData")]
        public string EncryptedPinData { get; set; }
    }
}
