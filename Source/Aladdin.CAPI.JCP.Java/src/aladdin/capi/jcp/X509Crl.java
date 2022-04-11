package aladdin.capi.jcp;
import aladdin.asn1.*;
import aladdin.asn1.iso.*;
import aladdin.asn1.iso.pkix.*;
import aladdin.capi.*;
import java.math.*;
import java.security.*;
import java.security.cert.*;
import javax.security.auth.x500.*; 
import java.io.*;
import java.util.*;

///////////////////////////////////////////////////////////////////////////////
// Список отозванных сертификатов
///////////////////////////////////////////////////////////////////////////////
public final class X509Crl extends java.security.cert.X509CRL
{
	private final Provider     provider;     // криптопровайдер
	private final CertificateList crl;          // список отозванных сертификатов
	
	// конструктор
	public X509Crl(Provider provider, CertificateList crl) 
    {
		// сохранить переданные параметры
		this.provider = provider; this.crl = crl; 
	}
	// закодированное представление
	@Override public final byte[] getEncoded() { return crl.encoded(); }
	// подписываемая часть списка
	@Override public final byte[] getTBSCertList() 
    { 
        // подписываемая часть списка
        return crl.tbsCertList().encoded(); 
    }
	// идентификатор алгоритма подписи
	@Override public final String getSigAlgName() { return getSigAlgOID(); }
	@Override public final String getSigAlgOID ()
	{
		// получить параметры алгоритма подписи
		AlgorithmIdentifier parameters = crl.signatureAlgorithm();
		
		// вернуть идентификатор алгоритма подписи
		return parameters.algorithm().value(); 
	}
	// параметры алгоритма подписи
	@Override public final byte[] getSigAlgParams()
	{
		// получить параметры алгоритма подписи
		AlgorithmIdentifier parameters = crl.signatureAlgorithm(); 

		// извлечь параметры алгоритма подписи
		IEncodable encodable = parameters.parameters(); 
		
		// вернуть параметры алгоритма подписи
        return (encodable != null) ? encodable.encoded() : null; 
	}
	// подпись списка
	@Override public final byte[] getSignature()
	{
		// вернуть подпись списка
		return crl.signature().value(); 
	}
    // версия структуры списка
	@Override public final int getVersion() 
	{
		// версия списка отозванных сертификатов
		return crl.tbsCertList().version().value().intValue(); 
	}
    // отличимое имя издателя
	@Override public final java.security.Principal getIssuerDN() 
	{
		// вернуть имя издателя
		return getIssuerX500Principal(); 
	}
    // дата выдачи списка
	@Override public final Date getThisUpdate() 
	{
		// получить дату выдачи списка
		VisibleString encodable = crl.tbsCertList().thisUpdate(); 
        
		// в зависимости от типа
		return (encodable instanceof UTCTime) ? 
		
			// раскодировать время
			((UTCTime)encodable).date() : ((GeneralizedTime)encodable).date(); 
	}
    // дата следующей выдачи списка
	@Override public final Date getNextUpdate() 
	{
		// получить дату следующей выдачи списка
		VisibleString encodable = crl.tbsCertList().nextUpdate(); 

		// в зависимости от типа
		return (encodable instanceof UTCTime) ? 
		
			// раскодировать время
			((UTCTime)encodable).date() : ((GeneralizedTime)encodable).date(); 
    }
    // отозванные сертификаты
	@Override
	public final java.util.Set<? extends X509CRLEntry> getRevokedCertificates() 
	{
		// создать список сертификатов
		java.util.Set<X509CRLEntry> certificates = new HashSet<X509CRLEntry>();
		
		// для всех отозванных сертификатов
		for (RevokedCertificate item : crl.tbsCertList().revokedCertificates())
		{
			// добавить сертификат в список
			certificates.add(new X509CrlEntry(item));
		}
		return certificates; 
	}
    // получить описание отзыва сертификата
	@Override public final X509CRLEntry getRevokedCertificate(BigInteger serialNumber) 
	{
		// для всех отозванных сертификатов
		for (RevokedCertificate certificate : crl.tbsCertList().revokedCertificates())
		{
			// проверить серийный номер сертификата
			if (certificate.userCertificate().value().equals(serialNumber))
			{
				// вернуть описание сертификата
				return new X509CrlEntry(certificate); 
			}
		}
		return null; 
	}
    // признак отозванного сертификата
	@Override public final boolean isRevoked(java.security.cert.Certificate cert) 
	{
        // идентификатор издателя и серийный номер сертификата
        java.security.Principal issuer = null; BigInteger serialNumber = null;

        // в зависимости от типа сертификата
        if (cert instanceof X509Certificate)
        {
            // преобразовать тип сертификата
            X509Certificate certificate = (X509Certificate)cert; 
            
            // извлечь идентификатор издателя
            issuer = certificate.getIssuerX500Principal(); 
            
            // извлечь серийный номер сертификата
            serialNumber = certificate.getSerialNumber();  
        }
        else try { 
            // раскодировать сертификат
            aladdin.capi.Certificate certificate = 
                new aladdin.capi.Certificate(cert.getEncoded()); 
            
            // указать идентификатор издателя
            issuer = new X500Principal(certificate.issuer().encoded()); 

            // извлечь серийный номер сертификата
            serialNumber = certificate.getSerialNumber();  
        }
        // обработать возможную ошибку
        catch (CertificateEncodingException e) { return false; }
        catch (IOException                  e) { return false; }
        
        // сравнить идентификаторы издателей
        if (!issuer.equals(getIssuerDN())) return false;  
        
		// для всех отозванных сертификатов
		for (RevokedCertificate item : crl.tbsCertList().revokedCertificates())
		{
			// проверить серийный номер сертификата
			if (item.userCertificate().value().equals(serialNumber)) return true; 
		}
		return false; 
	}
    // проверить наличие неподдерживаемых критичных расширений
	@Override public final boolean hasUnsupportedCriticalExtension() { return false; }
	
    // идентификаторы критичных расширений
	@Override public final java.util.Set<String> getCriticalExtensionOIDs()
	{
		// получить расширения списка
		Extensions extensions = crl.tbsCertList().attributes(); 
		
		// проверить наличие расширений
		if (extensions == null) return null;
		
		// создать список идентификаторов расширений
		java.util.Set<String> oids = new HashSet<String>(); 
		
		// для всех расширений сертификата
		for (aladdin.asn1.iso.pkix.Extension extension : extensions)
		{
			// определить идентификатор расширения
			String oid = extension.extnID().value(); 
			
			// проверить критичность расширения
			if (extension.critical().value()) oids.add(oid);
		}
		return oids; 
	}
    // идентификаторы некритичных расширений
	@Override public final java.util.Set<String> getNonCriticalExtensionOIDs()
	{
		// получить расширения сертификата
		Extensions extensions = crl.tbsCertList().attributes();
		
		// проверить наличие расширений
		if (extensions == null) return null;
		
		// создать список идентификаторов расширений
		java.util.Set<String> oids = new HashSet<String>(); 
		
		// для всех расширений сертификата
		for (aladdin.asn1.iso.pkix.Extension extension : extensions)
		{
			// определить идентификатор расширения
			String oid = extension.extnID().value(); 
			
			// проверить критичность расширения
			if (!extension.critical().value()) oids.add(oid);
		}
		return oids; 
	}
	// получить расширение сертификата
	@Override public final byte[] getExtensionValue(String oid)
	{
		// получить расширения сертификата
		Extensions extensions = crl.tbsCertList().attributes();
		
		// проверить наличие расширений
		if (extensions == null) return null;

		// найти требуемое расширение
		IEncodable encodable = extensions.get(oid); 
        
        // проверить наличие расширения
        if (encodable == null) return null; 
			
		// вернуть требуемое расширение
		return new OctetString(encodable.encoded()).encoded(); 
	}
	@Override
	public final void verify(java.security.PublicKey publicKey) 
		throws NoSuchAlgorithmException, InvalidKeyException, SignatureException 
	{
		// преобразовать тип ключа
		IPublicKey key = (IPublicKey)new KeyFactorySpi(provider).engineTranslateKey(publicKey); 
		
		// определить идентификатор алгоритма подписи
		AlgorithmIdentifier signParameters = crl.signatureAlgorithm(); 
		
		// извлечь значение подписи
		byte[] signature = crl.signature().value(); 
        
		// извлечь данные для подписи
        byte[] data = crl.tbsCertList().encoded();
		try { 
			// создать алгоритм подписи
			VerifyData verifyAlgorithm = (VerifyData)provider.factory().
                createAlgorithm(null, signParameters, VerifyData.class);
			
			// проверить наличие алгоритма
			if (verifyAlgorithm == null) throw new NoSuchAlgorithmException(); 
		
			// проверить подпись сертификата
			verifyAlgorithm.verify(key, data, 0, data.length, signature); 
		}
		// обработать возможную ошибку
		catch (IOException e) { throw new RuntimeException(e); }
	}
	@Override /* TODO */
	public final void verify(java.security.PublicKey publicKey, String provider) 
		throws NoSuchProviderException, NoSuchAlgorithmException, 
		InvalidKeyException, SignatureException 
	{
		// проверить подпись списка отозванных сертификатов
		if (provider.equals(this.provider.getName())) verify(publicKey); 

		// при ошибке выбросить исключение
		throw new NoSuchProviderException(); 
	}
	@Override
	public final String toString() { return getClass().toString(); } 
}
