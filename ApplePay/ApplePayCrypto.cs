using ApplePay.Base;
using ApplePay.Model;
using Newtonsoft.Json;

namespace ApplePay
{
    public static class ApplePayCrypto
    {
        #region 애플페이 토큰 서명 검증및 토큰 복호화
        /// <summary>
        /// 애플페이 토큰 서명 검증 및 결제 정보 복호화
        /// </summary>
        /// <param name="applePayJsonToken">애플페이 토큰(json string)</param>
        /// <returns>복호화된 Apple Payment Data 객체</returns>
        public static ApplePayDecryptedPaymentData VerifyNDecryptApplePayToken(string applePayJsonToken)
        {
            ApplePayPaymentToken token = JsonConvert.DeserializeObject<ApplePayPaymentToken>(applePayJsonToken);
            return VerifyNDecryptApplePayToken(token);
        }

        /// <summary>
        /// 애플페이 토큰 서명 검증 및 결제 정보 복호화
        /// 참조 : https://developer.apple.com/documentation/passkit/apple_pay/payment_token_format_reference
        /// </summary>
        /// <param name="ApplePayPaymentToken">애플페이 토큰 Object</param>
        /// <returns>복호화된 Apple Payment Data 객체</returns>
        public static ApplePayDecryptedPaymentData VerifyNDecryptApplePayToken(ApplePayPaymentToken token)
        {
            var applePay = ApplePayCryptoFactory.Create(token);

            /*STEP 1 : 서명 확인*/
            applePay.VerifyApplePaySignature(token);
            /*STEP 2 : Apple이 사용한 판매자 공개 키 판별 & 판매자 공개 키 인증서 및 개인 키 검색*/
            applePay.VerifyApplePayPaymentProcessingCertificate(token);
            /*STEP 3 : 대칭키 복원*/
            /*STEP 4 : 결제 데이터 복원*/
            var decryptedString = applePay.Decrypt(token);

            return JsonConvert.DeserializeObject<ApplePayDecryptedPaymentData>(decryptedString);
        }
        #endregion
    }
}
