using ApplePay.Model;

namespace ApplePay.Base
{
    internal class ApplePayCryptoFactory
    {
        public static ApplePayCryptoBase Create(ApplePayPaymentToken token)
        {
            ApplePayCryptoBase applePayCrypto = null;
            switch (token.PaymentData.Version)
            {
                case "EC_v1":
                    applePayCrypto = new ApplePayHelperForECC();
                    break;
                case "RSA_v1":
                    applePayCrypto = new ApplePayHelperForRsa();
                    break;
            }

            return applePayCrypto;
        }
    }
}
