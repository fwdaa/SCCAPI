using System;

namespace Aladdin.CAPI.PKCS12
{
    public static class ContainerFilter
    {
        ///////////////////////////////////////////////////////////////////////////
        // Поиск запроса на сертификат
        ///////////////////////////////////////////////////////////////////////////
        public class CertificationRequest : PfxFilter
        {
            // способ использования ключа и тип поиска
            private KeyUsage keyUsage; private bool set; private bool unknown; 
        
            // конструктор
            public CertificationRequest(KeyUsage keyUsage, bool set, bool unknown)
            { 
                // сохранить переданные параметры
                this.keyUsage = keyUsage; this.set = set; this.unknown = unknown; 
            } 
            // проверить соответствие объекта
            public override bool IsMatch(ASN1.ISO.PKCS.PKCS12.SafeBag safeBag, byte[] keyID) 
            {
			    // извлечь содержимое элемента
			    ASN1.ISO.PKCS.PKCS12.SecretBag secretBag = 
                    new ASN1.ISO.PKCS.PKCS12.SecretBag(safeBag.BagValue); 

                // создать объект запроса на сертификат
			    CertificateRequest request = new CertificateRequest(
				    secretBag.SecretValue.Content
			    ); 
			    // проверить способ использования ключа
			    if (unknown) return (request.KeyUsage == KeyUsage.None); 
	
                // проверить способ использования ключа
			    return (request.KeyUsage & keyUsage) == (set ? request.KeyUsage : keyUsage);
            }            
        }
        ///////////////////////////////////////////////////////////////////////////
        // Поиск запроса на сертификат
        ///////////////////////////////////////////////////////////////////////////
        public class CertificationRequestInfo : PfxFilter
        {
            // информация открытого ключа
            private ASN1.ISO.PKIX.SubjectPublicKeyInfo keyInfo; 
        
            // конструктор
            public CertificationRequestInfo(ASN1.ISO.PKIX.SubjectPublicKeyInfo keyInfo)
            { 
                // сохранить переданные параметры
                this.keyInfo = keyInfo; 
            } 
            // проверить соответствие объекта
            public override bool IsMatch(ASN1.ISO.PKCS.PKCS12.SafeBag safeBag, byte[] keyID) 
            {
			    // извлечь содержимое элемента
			    ASN1.ISO.PKCS.PKCS12.SecretBag secretBag = 
                    new ASN1.ISO.PKCS.PKCS12.SecretBag(safeBag.BagValue); 

			    // создать объект запроса на сертификат
			    CertificateRequest request = new CertificateRequest(secretBag.SecretValue.Content); 
            
			    // проверить совпадение открытого ключа
			    return request.PublicKeyInfo.Equals(keyInfo); 
            }            
        }
        ///////////////////////////////////////////////////////////////////////////
        // Поиск сертификата
        ///////////////////////////////////////////////////////////////////////////
        public class Certificate : PfxFilter
        {
            // способ использования ключа и тип поиска
            private KeyUsage keyUsage; private bool set; private bool unknown;
        
            // конструктор
            public Certificate() : this(KeyUsage.None, false, false) {}

            // конструктор
            public Certificate(KeyUsage keyUsage, bool set, bool unknown)
            { 
                // сохранить переданные параметры
                this.keyUsage = keyUsage; this.set = set; this.unknown = unknown; 
            } 
            // проверить соответствие объекта
            public override bool IsMatch(ASN1.ISO.PKCS.PKCS12.SafeBag safeBag, byte[] keyID) 
            {
			    // извлечь содержимое сертификата
			    byte[] content = new ASN1.ISO.PKCS.PKCS12.CertBag(safeBag.BagValue).CertValue.Content;

			    // создать сертификат по содержимому
			    CAPI.Certificate certificate = new CAPI.Certificate(content);
            
			    // проверить способ использования ключа
			    if (unknown) return (certificate.KeyUsage == KeyUsage.None); 

			    // проверить способ использования ключа
			    return (certificate.KeyUsage & keyUsage) == (set ? certificate.KeyUsage : keyUsage);
		    }
        }
        ///////////////////////////////////////////////////////////////////////////
        // Поиск сертификата
        ///////////////////////////////////////////////////////////////////////////
        public class CertificateInfo : PfxFilter
        {
            // информация открытого ключа
            private ASN1.ISO.PKIX.SubjectPublicKeyInfo keyInfo; 
        
            // конструктор
            public CertificateInfo(ASN1.ISO.PKIX.SubjectPublicKeyInfo keyInfo)
            { 
                // сохранить переданные параметры
                this.keyInfo = keyInfo; 
            } 
            // проверить соответствие объекта
            public override bool IsMatch(ASN1.ISO.PKCS.PKCS12.SafeBag safeBag, byte[] keyID) 
            {
			    // извлечь содержимое сертификата
			    byte[] content = new ASN1.ISO.PKCS.PKCS12.CertBag(safeBag.BagValue).CertValue.Content;

			    // создать сертификат по содержимому
			    CAPI.Certificate certificate = new CAPI.Certificate(content);
            
			    // проверить совпадение открытого ключа
			    return certificate.PublicKeyInfo.Equals(keyInfo);  
            }            
        }
        ///////////////////////////////////////////////////////////////////////////
        // Поиск личного ключа
        ///////////////////////////////////////////////////////////////////////////
        public class PrivateKeyInfo : PfxFilter
        {
            // информация открытого ключа
            private Factory factory; private ASN1.ISO.PKIX.SubjectPublicKeyInfo keyInfo; 
        
            // конструктор
            public PrivateKeyInfo(Factory factory, ASN1.ISO.PKIX.SubjectPublicKeyInfo keyInfo)
            { 
                // сохранить переданные параметры
                this.factory = factory; this.keyInfo = keyInfo; 
            } 
            // проверить соответствие объекта
            public override bool IsMatch(ASN1.ISO.PKCS.PKCS12.SafeBag safeBag, byte[] keyID) 
            {
			    // проверить тип личного ключа
			    if (safeBag.BagId.Value != ASN1.ISO.PKCS.PKCS12.OID.bt_key) return false;

			    // извлечь содержимое личного ключа
			    ASN1.ISO.PKCS.PKCS8.PrivateKeyInfo privateKeyInfo = 
                    new ASN1.ISO.PKCS.PKCS8.PrivateKeyInfo(safeBag.BagValue);

                // pаскодировать пару ключей
                using (KeyPair keyPair = factory.DecodeKeyPair(privateKeyInfo))
                {
                    // закодировать открытый ключ
                    ASN1.ISO.PKIX.SubjectPublicKeyInfo info = keyPair.PublicKey.Encoded; 

			        // проверить совпадение открытого ключа
			        return info.Equals(keyInfo);  
                } 
            }            
        }
    }
}
