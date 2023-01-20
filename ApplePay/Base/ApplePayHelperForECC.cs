/*
 * 소스 참조 : https://www.macrosssoftware.com/2019/10/12/decrypting-apple-pay-payment-blob-using-net-part-1-verify-the-signature/
 *           https://github.com/Macross-Software/ApplePayDecryption
 *           https://github.com/fscopel/CSharpApplePayDecrypter
 */
//#define KEY_FROM_CERTIFICATE
#define KEY_FROM_BASE64FORMAT
using ApplePay.Configuration;
using ApplePay.Extensions;
using ApplePay.Model;
using Org.BouncyCastle.Crypto.Agreement.Kdf;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System;
using System.Security.Cryptography.X509Certificates;
using System.Text;


namespace ApplePay.Base
{
    /// <summary> 
    /// ECC 인증서를 사용한 애플페이
    /// 사인 검증및 결제 데이터 복호화 클래스
    /// </summary>
    internal class ApplePayHelperForECC : ApplePayCryptoBase
    {
        #region Init Value
        protected static readonly byte[] s_ApplePayAlgorithmId = Encoding.UTF8.GetBytes((char)0x0d + "id-aes256-GCM");
        protected static readonly byte[] s_ApplePayPartyUInfo = Encoding.UTF8.GetBytes("Apple");
        #endregion

        #region 애플페이 서명 검증하기(Verify the Signature)
        /// <summary>
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
                || token.PaymentData?.Header?.EphemeralPublicKey == null
                || token.PaymentData?.Header?.TransactionId == null)
                throw new InvalidOperationException("Required signature data was not found on Payment Token JSON.");

            VerifyApplePaySignature(
                  rootCertificateAuthority
                , token.PaymentData.Signature
                , token.PaymentData.Data
                , token.PaymentData.Header.EphemeralPublicKey
                , token.PaymentData.Header.TransactionId.ToByteArray()
                , token.PaymentData.Header.ApplicationData?.ToByteArray()
                 //);
                , null);
        }
        #endregion

        #region 애플페이 PaymentData 복원 : 소스참조 - https://github.com/fscopel/CSharpApplePayDecrypter
        /// <summary>
        /// 애플페이 PaymentData 복호화 
        /// </summary>
        /// <returns>복호화된 애플페이 PaymentData</returns>
        public override string Decrypt(ApplePayPaymentToken token)
        {
            ECPrivateKeyParameters privateKey;
#if KEY_FROM_CERTIFICATE
            //Private Key 를 인증서에서 Export 하는 경우
            var paymentProcessingCertificate = GetPaymentProcessingCertification();
            privateKey = GetMerchantPrivateKey<ECPrivateKeyParameters>(paymentProcessingCertificate);
#endif
#if KEY_FROM_BASE64FORMAT
            //Private Key 를 별도의 키문자열에서 읽어 오는 경우
            privateKey = GetMerchantPrivateKey<ECPrivateKeyParameters>(Convert.FromBase64String(ApplePayConfig.PPCPrivateKeyBase64Format));
#endif
            var ephemeralPublicKey = Convert.FromBase64String(token.PaymentData.Header.EphemeralPublicKey);
            var publicKey = GetPublicKeyParameters<ECPublicKeyParameters>(ephemeralPublicKey);

            var sharedSecretBytes = GenerateSharedSecret(privateKey, publicKey);
            var encryptionKeyBytes = RestoreSymmetricKey(sharedSecretBytes);

            var decryptedBytes = DoDecrypt(Convert.FromBase64String(token.PaymentData.Data), encryptionKeyBytes);
            var decryptedString = Encoding.ASCII.GetString(decryptedBytes);

            return decryptedString;
        }

        private static byte[] GenerateSharedSecret(ECPrivateKeyParameters privateKey, ECPublicKeyParameters publicKeys)
        {
            var agree = AgreementUtilities.GetBasicAgreement("ECDH");
            agree.Init(privateKey);
            var sharedSecret = agree.CalculateAgreement(publicKeys);
            return sharedSecret.ToByteArrayUnsigned();
        }

        /// <summary>
        /// 애플페이 대칭키 복원(Restore a Symmetric Key for ECC)
        /// </summary>
        /// <param name="sharedSecretBytes"></param>
        /// <returns></returns>
        private byte[] RestoreSymmetricKey(byte[] sharedSecretBytes)
        {
            var merchantIdentifier = ExtractMIdentifier();

            var generator = new ConcatenationKdfGenerator(new Sha256Digest());
            var partyVInfoBytes = merchantIdentifier;
            var otherInfoBytes = Combine(Combine(s_ApplePayAlgorithmId, s_ApplePayPartyUInfo), partyVInfoBytes);

            generator.Init(new KdfParameters(sharedSecretBytes, otherInfoBytes));
            var encryptionKeyBytes = new byte[32];
            generator.GenerateBytes(encryptionKeyBytes, 0, encryptionKeyBytes.Length);

            return encryptionKeyBytes;
        }
        #endregion
    }
}
