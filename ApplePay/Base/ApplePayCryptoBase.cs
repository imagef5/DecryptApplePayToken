/*
 * 소스 참조 : https://www.macrosssoftware.com/2019/10/12/decrypting-apple-pay-payment-blob-using-net-part-1-verify-the-signature/
 *           https://github.com/Macross-Software/ApplePayDecryption
 *           https://github.com/fscopel/CSharpApplePayDecrypter
 */
using ApplePay.Configuration;
using ApplePay.Extensions;
using ApplePay.Model;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;
using System;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace ApplePay.Base
{
    internal enum LoadType
    {
        /// <summary>
        /// Base 64 String 에서 인증서 가져오기
        /// </summary>
        FromBase64,
        /// <summary>
        /// Hex String 에서 인증서 가져오기
        /// </summary>
        FromHex,
        /// <summary>
        /// 파일에서 인증서 가져오기
        /// </summary>
        FromDisk,
        /// <summary>
        /// 키 스토어에서 인증서 가져오기
        /// </summary>
        FromStore
    }
    /// <summary> 
    /// 애플페이 사인 검증및 결제 데이터 복호화 추상 클래스
    /// Payment Token Format Reference : https://developer.apple.com/documentation/passkit/apple_pay/payment_token_format_reference
    /// </summary>
    /// <see href="https://www.macrosssoftware.com/2019/10/12/decrypting-apple-pay-payment-blob-using-net-part-1-verify-the-signature/">애플페이 토큰 인증및 복호화</see>
    /// <seealso href="https://github.com/Macross-Software/ApplePayDecryption">애플페이 토큰 인증및 복호화 Github</see>
    /// <see href=https://github.com/fscopel/CSharpApplePayDecrypter/">애플페이 복호화 Github</see>
    internal abstract class ApplePayCryptoBase
    {
        #region Init Value
        protected static readonly byte[] s_ApplePayInitializationVector = new byte[16];
        #endregion

        #region 인증서 가져오기
        /// <summary>
        /// 애플 루트 인증서 가져오기
        /// Apple Root CA - G3
        /// https://www.apple.com/certificateauthority/
        /// </summary>
        /// <returns>Apple Root CA - G3 Certificate</returns>
        private protected X509Certificate2 GetRootCertificat(LoadType loadType = LoadType.FromBase64)
        {
            X509Certificate2 rootCertificateAuthority = null;
            X509Store authStore = null;
            X509Certificate2Collection certificates = null;
            string assemblyFolder = null;
            string cerFileName = null;

            switch (loadType)
            {
                case LoadType.FromBase64:
                    rootCertificateAuthority = new X509Certificate2(Convert.FromBase64String(ApplePayConfig.RootCertificationBase64Format));
                    break;
                case LoadType.FromHex:
                    rootCertificateAuthority = new X509Certificate2(ApplePayConfig.RootCertificationHexFormat.ToByteArray());
                    break;
                case LoadType.FromDisk:
                    assemblyFolder = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
                    cerFileName = Path.Combine(assemblyFolder, ApplePayConfig.RootCertificationFileName);
                    rootCertificateAuthority = new X509Certificate2(cerFileName);
                    break;
                case LoadType.FromStore:
                    authStore = new X509Store(StoreName.CertificateAuthority, StoreLocation.LocalMachine);
                    authStore.Open(OpenFlags.ReadOnly);

                    certificates = authStore.Certificates.Find(
                                        X509FindType.FindByThumbprint,
                                        ApplePayConfig.RootCertificationThumbprint,
                                        validOnly: false);
                    rootCertificateAuthority = (certificates.Count < 1) ? null : certificates[0];
                    break;
            }

            return rootCertificateAuthority;
        }
        /// <summary>
        /// 판매자 인증서 가져오기
        /// </summary>
        /// <returns>Payment Processing Certificate</returns>
        private protected X509Certificate2 GetPaymentProcessingCertification(LoadType loadType = LoadType.FromBase64)
        {

            X509Certificate2 paymentProcessingCertificate = null;
            X509Store authStore = null;
            X509Certificate2Collection certificates = null;
            string assemblyFolder = null;
            string cerFileName = null; 

            switch (loadType)
            {
                case LoadType.FromBase64:
                    paymentProcessingCertificate = new X509Certificate2(Convert.FromBase64String(ApplePayConfig.PPCBase64Format), ApplePayConfig.PPCPassword, X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.Exportable);
                    break;
                case LoadType.FromHex:
                    paymentProcessingCertificate = new X509Certificate2(ApplePayConfig.PPCHexFormat.ToByteArray(), ApplePayConfig.PPCPassword, X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.Exportable);
                    break;
                case LoadType.FromDisk:
                    assemblyFolder = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
                    cerFileName = Path.Combine(assemblyFolder, ApplePayConfig.PPCFileName);
                    paymentProcessingCertificate = new X509Certificate2(cerFileName, ApplePayConfig.PPCPassword, X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.Exportable);
                    break;
                case LoadType.FromStore:
                    authStore = new X509Store(StoreName.My, StoreLocation.LocalMachine);
                    authStore.Open(OpenFlags.ReadOnly);

                    certificates = authStore.Certificates.Find(
                                        X509FindType.FindByThumbprint,
                                        ApplePayConfig.PPCThumbprint,
                                        validOnly: false);
                    paymentProcessingCertificate = (certificates.Count < 1) ? null : certificates[0];
                    break;
            }

            return paymentProcessingCertificate;
        }
        #endregion

        #region 애플페이 서명 검증하기(Verify the Signature)
        /// <summary>
        /// 애플페이 토큰 서명 확인하기
        /// </summary>
        /// <param name="token">Apple Pay Payment Token</param>
        /// <returns></returns>
        //internal static bool VerifyApplePaySignature(ApplePayPaymentToken token)
        public abstract void VerifyApplePaySignature(ApplePayPaymentToken token);
        
        /// <summary>
        /// 애플페이 토큰 서명 확인하기
        /// </summary>
        /// <param name="rootCertificateAuthority">Apple 루트 CA - G3 인증서</param>
        /// <param name="signature">토큰 사인</param>
        /// <param name="data">애플페이 PaymentData data 전문(암호화된 결제 정보)</param>
        /// <param name="publicKeyString">PaymentData : Hedaer PublicKey String</param>
        /// <param name="headerTransactionId">PaymentData : Hedaer TransactionId</param>
        /// <param name="headerApplicationData">PaymentData : Hedaer ApplicationData</param>
        /// <param name="messageTimeToLiveInSeconds">서명 유효 시간</param>
        /// <param name="checkTimeToLive">서명 유효시간 체크 여부</param>
        private protected void VerifyApplePaySignature(
            X509Certificate2 rootCertificateAuthority,
            string signature,
            string data,
            string publicKeyString,
            byte[] headerTransactionId,
            byte[] headerApplicationData = null,
            int? messageTimeToLiveInSeconds = 60 * 5)
        {
            SignedCms SignedCms = new SignedCms(
                BuildContentForSignatureValidation(data, publicKeyString, headerTransactionId, headerApplicationData),
                detached: true);
            try
            {
                SignedCms.Decode(Convert.FromBase64String(signature));

                SignedCms.CheckSignature(verifySignatureOnly: true);
            }
            catch (Exception SignatureException)
            {
                throw new InvalidOperationException("ApplePay signature was invalid.", SignatureException);
            }

            (X509Certificate2 intermediaryCertificate, X509Certificate2 leafCertificate) = VerifySignatureCertificates(SignedCms.Certificates);
            VerifyCertificateChainTrust(rootCertificateAuthority, intermediaryCertificate, leafCertificate);
            if (messageTimeToLiveInSeconds.HasValue)
                VerifyApplePaySignatureSigningTime(SignedCms, messageTimeToLiveInSeconds.Value);
        }

        // <summary>
        /// 애플페이 토큰 데이터 읽기
        /// </summary>
        /// <param name="data">PaymentData 암호 전문(결제데이터)</param>
        /// <param name="publicKeyString">PaymentData Header PublicKey String</param>
        /// <param name="headerTransactionId">PaymentData Header TransactionId</param>
        /// <param name="headerApplicationData">PaymentData Header ApplicationData</param>
        /// <returns>CMS/PKCS #7 ContentInfo 데이터 구조체</returns>
        private protected ContentInfo BuildContentForSignatureValidation(
            string data,
            string publicKeyString,
            byte[] headerTransactionId,
            byte[] headerApplicationData)
        {
            using (MemoryStream ConcatenatedData = new MemoryStream())
            using (BinaryWriter Writer = new BinaryWriter(ConcatenatedData))
            {

                Writer.Write(Convert.FromBase64String(publicKeyString));
                Writer.Write(Convert.FromBase64String(data));
                Writer.Write(headerTransactionId);
                if (headerApplicationData != null)
                    Writer.Write(headerApplicationData);

                return new ContentInfo(ConcatenatedData.ToArray());
            }
        }

        /// <summary>
        /// 인증서에 올바른 사용자 지정 OID가 포함되어 있는지 확인하기
        /// 리프 인증서 OID :  1.2.840.113635.100.6.29
        /// 중간 CA OID : 1.2.840.113635.100.6.2.14
        /// </summary>
        /// <param name="signatureCertificates">CMS 메시지</param>
        /// <returns>(X509Certificate2 intermediaryCertificate, X509Certificate2 leafCertificate)</returns>
        private protected (X509Certificate2 intermediaryCertificate, X509Certificate2 leafCertificate) VerifySignatureCertificates(X509Certificate2Collection signatureCertificates)
        {
            if (signatureCertificates.Count != 2)
                throw new InvalidOperationException("ApplePay signature contained an invalid number of certificates.");

            X509Certificate2 IntermediaryCertificate = null;
            X509Certificate2 LeafCertificate = null;

            foreach (X509Certificate2 Certificate in signatureCertificates)
            {
                //Certificate.Extensions["Basic Constraints"] //Certificate.Extensions["기본 제한"]
                if (Certificate.Extensions["2.5.29.19"] is X509BasicConstraintsExtension BasicConstraintsExtension && BasicConstraintsExtension.CertificateAuthority)
                {
                    if (Certificate.Extensions["1.2.840.113635.100.6.2.14"] == null)
                        throw new InvalidOperationException("ApplePay signature intermediary certificate didn't contain Apple custom OID.");

                    IntermediaryCertificate = Certificate;
                    continue;
                }

                if (Certificate.Extensions["1.2.840.113635.100.6.29"] == null)
                    throw new InvalidOperationException("ApplePay signature leaf certificate didn't contain Apple custom OID.");

                LeafCertificate = Certificate;
            }

            if (LeafCertificate == null || IntermediaryCertificate == null)
                throw new InvalidOperationException("Intermediary and/or leaf certificates could not be found in PKCS7 signature.");

            return (IntermediaryCertificate, LeafCertificate);
        }

        /// <summary>
        /// 서명에서 루트 CA까지 유효한 X.509 신뢰 체인이 있는지 확인
        /// 서명이 리프 인증서에 해당하는 개인 키를 사용하여 생성되었는지, 
        /// 리프 인증서가 중간 CA에서 서명되었는지, 중간 CA가 Apple 루트 CA(G3)에 의해 서명되었는지 확인하기
        /// </summary>
        /// <param name="rootCertificateAuthority">Apple 루트 CA(G3) 인증서</param>
        /// <param name="intermediaryCertificate">중간 CA 인증서</param>
        /// <param name="leafCertificate">리프 인증서</param>
        private protected  void VerifyCertificateChainTrust(X509Certificate2 rootCertificateAuthority, X509Certificate2 intermediaryCertificate, X509Certificate2 leafCertificate)
        {
            X509Chain Chain = new X509Chain();

            Chain.ChainPolicy.ExtraStore.Add(intermediaryCertificate);
            Chain.ChainPolicy.ExtraStore.Add(rootCertificateAuthority);
            Chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;

            bool IsValid = Chain.Build(leafCertificate);

            IsValid = IsValid ||
                (Chain.ChainStatus.Length == 1 &&
                Chain.ChainStatus[0].Status == X509ChainStatusFlags.UntrustedRoot &&
                Chain.ChainPolicy.ExtraStore.Contains(Chain.ChainElements[Chain.ChainElements.Count - 1].Certificate));

            if (!IsValid)
                throw new InvalidOperationException("Certificate trust could not be established for PKCS7 signature certificates.");

        }

        /// <summary>
        /// 서명 시간 검사 
        /// 시간 서명과 트랜잭션 시간이 5분 이상 차이가 나는 경우 토큰은 재생 공격일 수 있습니다.
        /// </summary>
        /// <param name="signedCms">서명 CMS(RFC 5652의 섹션 11.3)</param>
        /// <param name="messageTimeToLiveInSeconds">서명 유효시간</param>
        private protected void VerifyApplePaySignatureSigningTime(SignedCms signedCms, int messageTimeToLiveInSeconds)
        {
            Oid SigningTimeOid = new Oid("1.2.840.113549.1.9.5");

            DateTime? SigningTime = null;
            foreach (SignerInfo SignerInfo in signedCms.SignerInfos)
            {
                foreach (CryptographicAttributeObject SignedAttribute in SignerInfo.SignedAttributes)
                {
                    if (SignedAttribute.Oid.Value == SigningTimeOid.Value && SignedAttribute.Values.Count > 0 && SignedAttribute.Values[0] is Pkcs9SigningTime Pkcs9SigningTime)
                    {
                        SigningTime = Pkcs9SigningTime.SigningTime;
                        break;
                    }
                }
            }

            if (!SigningTime.HasValue)
                throw new InvalidOperationException("ApplePay signature SigningTime OID was not found.");

            if (DateTime.UtcNow > SigningTime.Value.AddSeconds(messageTimeToLiveInSeconds))
                throw new InvalidOperationException("ApplePay message has expired.");
        }
        #endregion

        #region 애플페이 토큰 Header PublicKeyHash 값 유효성 검증하기
        /// <summary>
        /// 애플페이 토큰 Header PublicKeyHash 값 유효성 여부
        /// </summary>
        /// <param name="paymentProcessingCertificate"></param>
        /// <param name="token"></param>
        /// <returns>인증 유효성 여부</returns>
        //internal static book VerifyApplePayPaymentProcessingCertificate(ApplePayPaymentToken token)
        public void VerifyApplePayPaymentProcessingCertificate(ApplePayPaymentToken token)
        {
            var paymentProcessingCertificate = GetPaymentProcessingCertification();

            if (token.PaymentData?.Header?.PublicKeyHash == null)
                throw new InvalidOperationException("Required header data was not found on Payment Token JSON.");

            ValidatePaymentProcessingCertificate(
                paymentProcessingCertificate,
                token.PaymentData.Header.PublicKeyHash);
        }

        /// <summary>
        /// 애플페이 토큰 Header PublicKeyHash 값 유효성 검증하기
        /// </summary>
        /// <param name="paymentProcessingCertificate">지불처리 인증서</param>
        /// <param name="publicKeyHash"></param>
        private void ValidatePaymentProcessingCertificate(X509Certificate2 paymentProcessingCertificate, string publicKeyHash)
        {
            byte[] SuppliedCertificatePublicKeyHash = Convert.FromBase64String(publicKeyHash);

            using (HashAlgorithm SHA = new SHA256CryptoServiceProvider())
            {
                byte[] CalculatedHash = SHA.ComputeHash(paymentProcessingCertificate.ExportPublicKeyInDERFormat());

                if (!SuppliedCertificatePublicKeyHash.SequenceEqual(CalculatedHash))
                    throw new InvalidOperationException("Payment processing certificate does not match the publicKeyHash on the payment data.");
            }
            if (!paymentProcessingCertificate.HasPrivateKey)
                throw new InvalidOperationException("Payment processing certificate does not have a private key.");
        }
        #endregion

        #region 애플페이 PaymentData 복원 : 소스참조 - https://github.com/fscopel/CSharpApplePayDecrypter
        /// <summary>
        /// 애플페이 PaymentData 복원 
        /// </summary>
        /// <returns></returns>
        public abstract string Decrypt(ApplePayPaymentToken token);


        private protected T GetPublicKeyParameters<T>(byte[] ephemeralPublicKeyBytes) where T : AsymmetricKeyParameter
        {
            return (T)PublicKeyFactory.CreateKey(ephemeralPublicKeyBytes);
        }
        /// <summary>
        /// Certificate Private Key 가져오기
        /// </summary>
        /// <typeparam name="T">키형식</typeparam>
        /// <param name="certificate">인증서</param>
        /// <param name="password">패스워드</param>
        /// <returns>키형식</returns>
        private protected T GetMerchantPrivateKey<T>(X509Certificate2 certificate, string password = "") where T : AsymmetricKeyParameter
        {
            byte[] pkcs12Bytes = certificate.Export(X509ContentType.Pkcs12, password);
            Pkcs12Store pkcs12 = new Pkcs12StoreBuilder().Build();
            T privKey = null;
            using (MemoryStream stream = new MemoryStream(pkcs12Bytes, false))
            {
                pkcs12.Load(stream, password?.ToCharArray());
                string alias = pkcs12.Aliases.Cast<string>().FirstOrDefault(al => pkcs12.IsKeyEntry(al) && pkcs12.GetKey(al).Key.IsPrivate);
                if (!string.IsNullOrEmpty(alias))
                {
                    privKey = (T)pkcs12.GetKey(alias).Key;
                }
            }

            if (privKey == null)
            {
                throw new InvalidOperationException("Payment processing certificate does not have a private key.");
            }

            return privKey;
        }
        /// <summary>
        /// Certificate Private Key 가져오기
        /// </summary>
        /// <typeparam name="T">키형식</typeparam>
        /// <param name="privateKeyBite">개인키 Bytes 배열</param>
        /// <returns>키형식</returns>
        private protected T GetMerchantPrivateKey<T>(byte[] privateKeyBite) where T : AsymmetricKeyParameter
        {
            var akp = PrivateKeyFactory.CreateKey(privateKeyBite);
            return (T)akp;
        }

        /// <summary>
        /// merchant identifier 가져오기
        /// </summary>
        /// <returns></returns>
        private protected byte[] ExtractMIdentifier()
        {
            var merchantCertificate = GetPaymentProcessingCertification();// new X509Certificate2(ApplePayConfig.PaymentProcessingCertificationHexFormat.ToByteArray());
            var merchantIdentifierTlv = merchantCertificate.Extensions["1.2.840.113635.100.6.32"]?.RawData;
            if (merchantIdentifierTlv == null)
            {
                throw new InvalidOperationException("Payment processing certificate does not have a merchant identifier field.");
            }
            var merchantIdentifier = new byte[64];
            Buffer.BlockCopy(merchantIdentifierTlv, 2, merchantIdentifier, 0, 64);
            
            return Hex.Decode(Encoding.ASCII.GetString(merchantIdentifier));

            //return Encoding.ASCII.GetString(merchantIdentifierTlv).Substring(2).ToByteArray();
        }

        private protected byte[] Combine(byte[] first, byte[] second)
        {
            var ret = new byte[first.Length + second.Length];
            Buffer.BlockCopy(first, 0, ret, 0, first.Length);
            Buffer.BlockCopy(second, 0, ret, first.Length, second.Length);
            return ret;
        }

        private protected byte[] DoDecrypt(byte[] cipherData, byte[] encryptionKeyBytes)
        {
            var keyParam = ParameterUtilities.CreateKeyParameter("AES", encryptionKeyBytes);
            var parameters = new ParametersWithIV(keyParam, s_ApplePayInitializationVector);
            var cipher = GetCipher();
            cipher.Init(false, parameters);
            var output = cipher.DoFinal(cipherData);

            return output;
        }

        public static IBufferedCipher GetCipher()
        {
            return CipherUtilities.GetCipher("AES/GCM/NoPadding");
        }

        #endregion
    }
}
