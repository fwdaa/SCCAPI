package aladdin.capi.pkcs12;
import aladdin.*; 
import aladdin.asn1.iso.pkcs.pkcs12.*;
import aladdin.asn1.iso.pkix.*;
import aladdin.capi.*;
import java.io.*;

public final class ContainerFilter 
{
    ///////////////////////////////////////////////////////////////////////////
    // Поиск запроса на сертификат
    ///////////////////////////////////////////////////////////////////////////
    public static class CertificationRequest extends PfxFilter
    {
        // способ использования ключа и тип поиска
        private final KeyUsage keyUsage; private final boolean set; private final boolean unknown; 
        
        // конструктор
        public CertificationRequest(KeyUsage keyUsage, boolean set, boolean unknown)
        { 
            // сохранить переданные параметры
            this.keyUsage = keyUsage; this.set = set; this.unknown = unknown; 
        } 
        // проверить соответствие объекта
        @Override public boolean isMatch(SafeBag safeBag, byte[] keyID) throws IOException
        {
			// извлечь содержимое элемента
			SecretBag secretBag = new SecretBag(safeBag.bagValue()); 

            // создать объект запроса на сертификат
			CertificateRequest request = new CertificateRequest(
				secretBag.secretValue().content()
			); 
			// проверить способ использования ключа
			if (unknown) return (request.keyUsage().isEmpty()); if (set)
            {
                // проверить способ использования ключа
                return keyUsage.containsAll(request.keyUsage()); 
            }
            // проверить способ использования ключа
            else return request.keyUsage().containsAll(keyUsage); 
        }            
    }
    ///////////////////////////////////////////////////////////////////////////
    // Поиск запроса на сертификат
    ///////////////////////////////////////////////////////////////////////////
    public static class CertificationRequestInfo extends PfxFilter
    {
        // информация открытого ключа
        private final SubjectPublicKeyInfo keyInfo; 
        
        // конструктор
        public CertificationRequestInfo(SubjectPublicKeyInfo keyInfo)
        { 
            // сохранить переданные параметры
            this.keyInfo = keyInfo; 
        } 
        // проверить соответствие объекта
        @Override public boolean isMatch(SafeBag safeBag, byte[] keyID) throws IOException
        {
			// извлечь содержимое элемента
			SecretBag secretBag = new SecretBag(safeBag.bagValue()); 

			// создать объект запроса на сертификат
			CertificateRequest request = new CertificateRequest(secretBag.secretValue().content()); 
            
			// проверить совпадение открытого ключа
			return request.publicKeyInfo().equals(keyInfo); 
        }            
    }
    ///////////////////////////////////////////////////////////////////////////
    // Поиск сертификата
    ///////////////////////////////////////////////////////////////////////////
    public static class Certificate extends PfxFilter
    {
        // способ использования ключа и тип поиска
        private final KeyUsage keyUsage; private final boolean set; private final boolean unknown;
        
        // конструктор
        public Certificate() { this(KeyUsage.NONE, false, false); }
        
        // конструктор
        public Certificate(KeyUsage keyUsage, boolean set, boolean unknown)
        { 
            // сохранить переданные параметры
            this.keyUsage = keyUsage; this.set = set; this.unknown = unknown; 
        } 
        // проверить соответствие объекта
        @Override public boolean isMatch(SafeBag safeBag, byte[] keyID) throws IOException
        {
			// извлечь содержимое сертификата
			byte[] content = new CertBag(safeBag.bagValue()).certValue().content();

			// создать сертификат по содержимому
			aladdin.capi.Certificate certificate = new aladdin.capi.Certificate(content);
            
			// проверить способ использования ключа
			if (unknown) return (certificate.keyUsage().isEmpty()); if (set)
            {
                // проверить способ использования ключа
                return keyUsage.containsAll(certificate.keyUsage()); 
            }
            // проверить способ использования ключа
            else return certificate.keyUsage().containsAll(keyUsage);
		}
    }
    ///////////////////////////////////////////////////////////////////////////
    // Поиск сертификата
    ///////////////////////////////////////////////////////////////////////////
    public static class CertificateInfo extends PfxFilter
    {
        // информация открытого ключа
        private final SubjectPublicKeyInfo keyInfo; 
        
        // конструктор
        public CertificateInfo(SubjectPublicKeyInfo keyInfo)
        { 
            // сохранить переданные параметры
            this.keyInfo = keyInfo; 
        } 
        // проверить соответствие объекта
        @Override public boolean isMatch(SafeBag safeBag, byte[] keyID) throws IOException
        {
			// извлечь содержимое сертификата
			byte[] content = new CertBag(safeBag.bagValue()).certValue().content();

			// создать сертификат по содержимому
			aladdin.capi.Certificate certificate = new aladdin.capi.Certificate(content);
            
			// проверить совпадение открытого ключа
			return certificate.publicKeyInfo().equals(keyInfo);  
        }            
    }
    ///////////////////////////////////////////////////////////////////////////
    // Поиск личного ключа
    ///////////////////////////////////////////////////////////////////////////
    public static class PrivateKeyInfo extends PfxFilter
    {
        // информация открытого ключа
        private final Factory factory; private final SubjectPublicKeyInfo keyInfo; 
        
        // конструктор
        public PrivateKeyInfo(Factory factory, SubjectPublicKeyInfo keyInfo)
        { 
            // сохранить переданные параметры
            this.factory = RefObject.addRef(factory); this.keyInfo = keyInfo; 
        } 
        // проверить соответствие объекта
        @Override public boolean isMatch(SafeBag safeBag, byte[] keyID) throws IOException
        {
    	    // проверить тип личного ключа
		    if (!safeBag.bagId().value().equals(aladdin.asn1.iso.pkcs.pkcs12.OID.BT_KEY)) return false;

		    // извлечь содержимое личного ключа
		    aladdin.asn1.iso.pkcs.pkcs8.PrivateKeyInfo privateKeyInfo = 
                new aladdin.asn1.iso.pkcs.pkcs8.PrivateKeyInfo(safeBag.bagValue());

            // pаскодировать пару ключей
            try (KeyPair keyPair = factory.decodeKeyPair(privateKeyInfo))
            {
                // закодировать открытый ключ
                SubjectPublicKeyInfo info = keyPair.publicKey.encoded(); 
                
                // проверить совпадение открытого ключа
		        return info.equals(keyInfo);  
            } 
        }            
    }
}
