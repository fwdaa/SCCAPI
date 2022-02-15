package aladdin.capi.jcp;
import java.security.*;
import java.security.cert.*;
import java.util.*;

///////////////////////////////////////////////////////////////////////////////
// Хранилище сертификатов
///////////////////////////////////////////////////////////////////////////////
public final class X509CertStoreSpi extends java.security.cert.CertStoreSpi
{
	// хранилище сертификатов
	private final CollectionCertStoreParameters parameters; 
	
	// конструктор
	public X509CertStoreSpi(CollectionCertStoreParameters parameters) 
        throws InvalidAlgorithmParameterException
	{
		// сохранить переданные параметры
		super(parameters); this.parameters = parameters;
	}
	@Override
	public Collection<? extends java.security.cert.Certificate> 
        engineGetCertificates(CertSelector selector) throws CertStoreException 
	{
		// создать список сертификатов
		List<java.security.cert.Certificate> certificates = 
			new ArrayList<java.security.cert.Certificate>(); 
		
		// для каждого Объекта хранилища
		for (Object obj : parameters.getCollection())
		{
			// проверить тип объекта
			if (!(obj instanceof java.security.cert.Certificate)) continue; 
			
			// преобразовать тип сертификата
			java.security.cert.Certificate certificate = (java.security.cert.Certificate)obj; 
			
			// проверить совпадение сертификата
			if (selector.match(certificate)) certificates.add(certificate);
		}
		return certificates; 
	}
	@Override
	public Collection<? extends CRL> 
        engineGetCRLs(CRLSelector selector) throws CertStoreException 
	{
		// создать список списков отозванных сертификатов
		List<java.security.cert.CRL> crls = new ArrayList<java.security.cert.CRL>(); 
		
		// для каждого Объекта хранилища
		for (Object obj : parameters.getCollection())
		{
			// проверить тип объекта
			if (!(obj instanceof java.security.cert.CRL)) continue; 
			
			// преобразовать тип списка отозванных сертификатов
			java.security.cert.CRL crl = (java.security.cert.CRL)obj; 
			
			// проверить совпадение списка отозванных сертификатов
			if (selector.match(crl)) crls.add(crl);
		}
		return crls; 
	}
}
