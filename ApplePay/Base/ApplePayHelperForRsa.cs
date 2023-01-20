//#define KEY_FROM_CERTIFICATE
#define KEY_FROM_BASE64FORMAT
using ApplePay.Configuration;
using ApplePay.Extensions;
using ApplePay.Model;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace ApplePay.Base
{
    /// <summary> 
    /// (China Only)
    /// RSA 인증서를 사용한 애플페이
    /// 사인 검증및 결제 데이터 복호화 클래스
    /// </summary>
    internal class ApplePayHelperForRsa : ApplePayCryptoBase
    {
        #region 애플페이 서명 검증하기(Verify the Signature)
        // <summary>
        /// 애플페이 토큰 서명 확인하기
        /// </summary>
        /// <param name="token">Apple Pay Payment Token</param>
        /// <returns></returns>
        //internal static bool VerifyApplePaySignature(ApplePayPaymentToken token)
        public override void VerifyApplePaySignature(ApplePayPaymentToken token)
        {
            X509Certificate2 rootCertificateAuthority = GetRootCertificat();

            if (token.PaymentData?.Signature == null
                || token.PaymentData?.Data == null
                || token.PaymentData?.Header?.WrappedKey == null
                || token.PaymentData?.Header?.TransactionId == null)
                throw new InvalidOperationException("Required signature data was not found on Payment Token JSON.");

            VerifyApplePaySignature(
                  rootCertificateAuthority
                , token.PaymentData.Signature
                , token.PaymentData.Data
                , token.PaymentData.Header.WrappedKey
                , token.PaymentData.Header.TransactionId.ToByteArray()
                , token.PaymentData.Header.ApplicationData?.ToByteArray()
                );
                //, null);
            //throw new NotImplementedException("RSA_v1 is only available in China.");
        }
        #endregion

        #region 대칭키 복원 및 토큰 복호화
        /// <summary>
        /// 애플페이 PaymentData 복호화 
        /// </summary>
        /// <returns>복호화된 애플페이 PaymentData</returns>
        public override string Decrypt(ApplePayPaymentToken token)
        {
            RsaPrivateCrtKeyParameters privateKey;
#if KEY_FROM_CERTIFICATE
            //Private Key 를 인증서에서 Export 하는 경우
            var paymentProcessingCertificate = GetPaymentProcessingCertification();
            privateKey = GetMerchantPrivateKey<RsaPrivateCrtKeyParameters>(paymentProcessingCertificate);
#endif
#if KEY_FROM_BASE64FORMAT
            //Private Key 를 별도의 키문자열에서 읽어 오는 경우
            privateKey = GetMerchantPrivateKey<RsaPrivateCrtKeyParameters>(Convert.FromBase64String(ApplePayConfig.PPCPrivateKeyBase64Format));
#endif
            var wrappedPublicKey = Convert.FromBase64String(token.PaymentData.Header.WrappedKey);
            var encryptionKeyBytes = RestoreSymmetricKey(privateKey, wrappedPublicKey);

            var decryptedBytes = DoDecrypt(Convert.FromBase64String(token.PaymentData.Data), encryptionKeyBytes);
            var decryptedString = Encoding.ASCII.GetString(decryptedBytes);

            return decryptedString;
        }

        /// <summary>
        /// 애플페이 대칭키 복원(Restore a Symmetric Key for RSA)
        /// </summary>
        /// <param name="ICipherParameters">Private Key Parameters</param>
        /// <param name="encrypted">암호화된 Public Key Bytes Array</param>
        /// <returns></returns>
        private static byte[] RestoreSymmetricKey(ICipherParameters keyParam, byte[] encrypted)
        {
            var decrypter = new OaepEncoding(new RsaEngine(), new Sha256Digest(), new Sha256Digest(), null);
            decrypter.Init(false, keyParam);
            byte[] decrypted = decrypter.ProcessBlock(encrypted, 0, encrypted.Length);

            return decrypted;
        }
        #endregion
    }
}
