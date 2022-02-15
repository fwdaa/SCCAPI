using System;

namespace Aladdin.CAPI
{
    /////////////////////////////////////////////////////////////////////////////////////////////////////////
    // Области использования ключа
    /////////////////////////////////////////////////////////////////////////////////////////////////////////
    // 1)	При создании ключа необходимо указать KeyUsage (способ использования данного ключа). 
    //     KeyUsage может быть любой битовой комбинацией из перечисления KeyUsage. На основании 
    //     определенного алгоритма (специфического для каждого провайдера) по KeyUsage определяется 
    //     способ идентификации данного ключа в контейнере: например, если контейнер – программный PKCS12, 
    //     то все биты KeyUsage используются при идентификации; если контейнер – это контейнер CSP, 
    //     то на основании KeyUsage определяется слот AT_KEYEXCHANGE или AT_SIGNATURE (см. далее). 
    // 2)	При вызове последующих функций связанных с ключами (генерация запроса на сертификат, 
    //     генерация сертификата) необходимо использовать KeyUsage, указанный при создании ключа. 
    // 
    // Для контейнеров CSP определение слота при генерации производится следующим образом: 
    // 1)	входной KeyUsage расширяется так, что если установлен хотя бы один бит из маски keyExchange, 
    //     то устанавливаются все биты из keyExchange и если установлен хотя бы один бит из маски dataSignature, 
    //     то устанавливаются все биты из dataSignature; 
    // 2)	для каждого слота (AT_KEYEXCHANGE, AT_SIGNATURE) определяется собственный KeyUsage (slotKeyUsage):
    // a.	для слота AT_KEYEXCHANGE: 
    //       slotKeyUsage = KeyUsage.keyExchange   | KeyUsage сертификата слота (при его наличии);
    // b.	для слота AT_SIGNATURE: 
    //       slotKeyUsage = KeyUsage.dataSignature | KeyUsage сертификата слота (при его наличии).
    // 3)	Из slotKeyUsage убираются все биты не принадлежащие маске keyExchange | dataSignature 
    //     (они могут быть при наличии сертификатов). 
    // 4)	Выбранным слотом является первый слот из последовательности (AT_KEYEXCHANGE, AT_SIGNATURE), 
    //     для которого входной расширенный KeyUsage полностью содержит slotKeyUsage. 
    // 5)	Если таких слотов  нет, то 
    // a.	выбирается AT_KEYEXCHANGE при установке в KeyUsage битов из keyExchange;
    // b.	выбирается AT_SIGNATURE   при установке в KeyUsage битов из dataSignature;
    // c.	выбирается AT_KEYEXCHANGE. 
    // 
    // Если для контейнеров CSP пользоваться тривиальным случаем (два ключа содержат непересекающиеся KeyUsage – 
    // один из маски keyExchange, другой – из маски dataSignature), то соответствие KeyUsage слоту тривиально. 
    /////////////////////////////////////////////////////////////////////////////////////////////////////////
	[Flags] public enum KeyUsage : long
	{
        None					= ASN1.ISO.PKIX.CE.KeyUsage.None,  
		DigitalSignature		= ASN1.ISO.PKIX.CE.KeyUsage.DigitalSignature,  
		NonRepudiation			= ASN1.ISO.PKIX.CE.KeyUsage.NonRepudiation, 
		KeyEncipherment			= ASN1.ISO.PKIX.CE.KeyUsage.KeyEncipherment,
		DataEncipherment		= ASN1.ISO.PKIX.CE.KeyUsage.DataEncipherment,
		KeyAgreement			= ASN1.ISO.PKIX.CE.KeyUsage.KeyAgreement,
		CertificateSignature	= ASN1.ISO.PKIX.CE.KeyUsage.CertificateSignature,
		CrlSignature			= ASN1.ISO.PKIX.CE.KeyUsage.CrlSignature,
		EncipherOnly			= ASN1.ISO.PKIX.CE.KeyUsage.EncipherOnly,
		DecipherOnly			= ASN1.ISO.PKIX.CE.KeyUsage.DecipherOnly, 
	}
}
