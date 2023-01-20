# Decrypting Apple Pay Token  
## 1. 원본 소스
- [Decrypting Apple Pay Payment Blob Using .NET](https://www.macrosssoftware.com/2019/10/12/decrypting-apple-pay-payment-blob-using-net/)
  - [Github Source Code](https://github.com/Macross-Software/ApplePayDecryption)
- [How to decrypt Apple Pay Payment Token using .net](https://github.com/fscopel/CSharpApplePayDecrypter#how-to-decrypt-apple-pay-payment-token-using-net)
> .net 프로젝트를 진행하다보면 많은 소스들이 .net 4.5 framework 에서 업그레드가 되지 않고 현재까지 유지되어 오는 경우가 많은 것이 현실이고, 기업 규모가 클수록 더욱 변경이 쉽지 않아 개인적으로는 아쉬움이 있습니다. 해당 소스는 위 두소스를 참조하여 .net 4.5 framework 에 맞춰 변경 되었습니다.  
> .net 4.5 이상을 사용하신다면 위 소스를 참조 하시기 바랍니다.
  
## 2. 애플페이 관련 참조
- [Apple Pay 설정](https://developer.apple.com/documentation/passkit/apple_pay/setting_up_apple_pay)
- [Payment Token Format Reference](https://developer.apple.com/documentation/passkit/apple_pay/payment_token_format_reference)

## 3. 인증서 불러오기
- IIS 상에서 인증서 불러오기 및 Private Key Export 주의 사항
  - 인증서 불러오기 설정시 **X509KeyStorageFlags.MachineKeySet** 옵션 설정
    ``` 
    paymentProcessingCertificate = new X509Certificate2(certificate, "password", X509KeyStorageFlags.MachineKeySet);

    or
    //With Private Key Export
    paymentProcessingCertificate = new X509Certificate2(certificate, "password", X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.Exportable);
    ``` 
  - Private Key Export 시 IIS 프로세스 권한 문제로 인해 인증서 Loading 후 Private Key 내보내기를 하기 보다 openssl 을 이용하여 별도의 Private Key 문자열을 생성하여 처리 하는것을 권장합니다.
  - IIS 상에서 인증서를 Loading 후 Private key 내보내기를 원한경우 [여기](https://stackoverflow.com/questions/2609859/how-to-give-asp-net-access-to-a-private-key-in-a-certificate-in-the-certificate)를 참조 하세요.