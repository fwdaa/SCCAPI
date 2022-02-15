package aladdin.capi.jcp;
import aladdin.asn1.*;
import aladdin.asn1.iso.pkix.*;
import java.math.*;
import java.util.*;

///////////////////////////////////////////////////////////////////////////////
// Отозванный сертификат
///////////////////////////////////////////////////////////////////////////////
public final class X509CrlEntry extends java.security.cert.X509CRLEntry
{
    // описание отозванного сертификата
	private final RevokedCertificate certificate;
	
	// конструктор
	public X509CrlEntry(RevokedCertificate certificate) 
	{
		// сохранить сертификат
		this.certificate = certificate; 
	}
    // закодированное представление
	@Override public final byte[] getEncoded() { return certificate.encoded(); } 
	
    // серийный номер сертификата
	@Override public final BigInteger getSerialNumber() 
	{
		// серийный номер сертификата
		return certificate.userCertificate().value(); 
	}
	// дата отзыва сертификата
	@Override public final Date getRevocationDate() 
	{
		// получить дату отзыва сертификата
		VisibleString encodable = certificate.revocationDate(); 
        
		// в зависимости от типа
		return (encodable instanceof UTCTime) ? 
		
			// раскодировать время
			((UTCTime)encodable).date() : ((GeneralizedTime)encodable).date(); 
	}
    // проверить наличие расширений
	@Override public final boolean hasExtensions() 
	{
		// проверить наличие расширений
		return certificate.crlEntryExtensions() != null; 
	}
    // проверить наличие неподдерживаемых критичных расширений
	@Override public final boolean hasUnsupportedCriticalExtension() { return false; }
	
    // идентификаторы критичных расширений
	@Override public final java.util.Set<String> getCriticalExtensionOIDs()
	{
		// получить расширения списка
		Extensions extensions = certificate.crlEntryExtensions(); 
		
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
		Extensions extensions = certificate.crlEntryExtensions();
		
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
		Extensions extensions = certificate.crlEntryExtensions();
		
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
	public final String toString() { return getClass().toString(); } 
}
