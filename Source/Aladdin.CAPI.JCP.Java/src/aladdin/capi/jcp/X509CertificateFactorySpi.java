package aladdin.capi.jcp;
import aladdin.asn1.*;
import aladdin.asn1.iso.pkcs.pkcs7.*;
import java.security.cert.*;
import java.io.*;
import java.util.*;

///////////////////////////////////////////////////////////////////////////////
// Фабрика сертификатов X.509
///////////////////////////////////////////////////////////////////////////////
public final class X509CertificateFactorySpi extends java.security.cert.CertificateFactorySpi
{
	// конструктор
	public X509CertificateFactorySpi(Provider provider)
	
		// сохранить переданные параметры
		{ this.provider = provider; } private final Provider provider; 
	
	@Override
	public final java.util.Collection<? extends Certificate> 
        engineGenerateCertificates(InputStream stream) throws CertificateException 
    {
        // выделить динамический буфер
        ByteArrayOutputStream memoryStream = new ByteArrayOutputStream(); 
        try { 
            // прочитать данные во вспомогательный буфер
            byte[] buffer = new byte[4096]; int cb = stream.read(buffer); 

            // до окончания потока
            while (cb == buffer.length)
            {
                // сохранить прочитанные данные
                memoryStream.write(buffer); cb = stream.read(buffer); 
            }
            // сохранить прочитанные данные
            memoryStream.write(buffer, 0, cb); 
        }
        // обработать возможную ошибку
        catch (IOException e) { throw new CertificateException(e.getMessage()); }

        // раскодировать сертификат
        return engineGenerateCertificates(memoryStream.toByteArray()); 
    }
	public final java.util.Collection<? extends Certificate> 
        engineGenerateCertificates(byte[] encoded) throws CertificateException 
    {
		// создать список сертификатов
		List<java.security.cert.Certificate> list = 
			new ArrayList<java.security.cert.Certificate>(); 
        try {
            // раскодировать подписанные данные
            SignedData signedData = new SignedData(Encodable.decode(encoded)); 
            
            // для всех сертификатов из списка
            for (IEncodable encodable : signedData.certificates())
            {
                // проверить наличие сертификата X.509
                if (encodable.tag().equals(Tag.SEQUENCE)) continue; 
                
                // добавить сертификат в список
                list.add(new aladdin.capi.Certificate(encodable.encoded())); 
            }
        }
        // раскодировать отдельный сертификат
        catch (IOException e) { list.add(engineGenerateCertificate(encoded)); } return list;  
    }
	@Override
	public final Certificate engineGenerateCertificate(InputStream stream) 
		throws CertificateException 
    {
        // выделить динамический буфер
        ByteArrayOutputStream memoryStream = new ByteArrayOutputStream(); 
        try { 
            // прочитать данные во вспомогательный буфер
            byte[] buffer = new byte[4096]; int cb = stream.read(buffer); 

            // до окончания потока
            while (cb == buffer.length)
            {
                // сохранить прочитанные данные
                memoryStream.write(buffer); cb = stream.read(buffer); 
            }
            // сохранить прочитанные данные
            memoryStream.write(buffer, 0, cb); 
        }
        // обработать возможную ошибку
        catch (IOException e) { throw new CertificateException(e.getMessage()); }
        
        // раскодировать сертификат
        return engineGenerateCertificate(memoryStream.toByteArray()); 
	}
	public final Certificate engineGenerateCertificate(byte[] encoded) 
		throws CertificateException 
    {
        try {
            // создать объект сертификата
            return new aladdin.capi.Certificate(encoded); 
        }
        // обработать возможную ошибку
        catch (IOException e) { throw new CertificateException(e.getMessage()); }
    }
	@Override
	public final java.util.Collection<? extends CRL> 
        engineGenerateCRLs(InputStream stream) throws CRLException 
    {
        // выделить динамический буфер
        ByteArrayOutputStream memoryStream = new ByteArrayOutputStream(); 
        try { 
            // прочитать данные во вспомогательный буфер
            byte[] buffer = new byte[4096]; int cb = stream.read(buffer); 

            // до окончания потока
            while (cb == buffer.length)
            {
                // сохранить прочитанные данные
                memoryStream.write(buffer); cb = stream.read(buffer); 
            }
            // сохранить прочитанные данные
            memoryStream.write(buffer, 0, cb); 
        }
        // обработать возможную ошибку
        catch (IOException e) { throw new CRLException(e.getMessage()); }
        
        // раскодировать списки отозванных сертификатов
        return engineGenerateCRLs(memoryStream.toByteArray()); 
	}
	public final java.util.Collection<? extends CRL> 
        engineGenerateCRLs(byte[] encoded) throws CRLException 
    {
		// создать список сертификатов
		List<java.security.cert.CRL> list = 
			new ArrayList<java.security.cert.CRL>(); 
        try {
            // раскодировать подписанные данные
            SignedData signedData = new SignedData(Encodable.decode(encoded)); 
            
            // для всех списков отозванных сертификатов
            for (IEncodable encodable : signedData.crls())
            {
                // проверить наличие списка X.509
                if (encodable.tag().equals(Tag.SEQUENCE)) continue; 
                
                // раскодировать список отозванных сертификатов X.509
                aladdin.asn1.iso.pkix.CertificateList crl = 
                    new aladdin.asn1.iso.pkix.CertificateList(encodable); 
                
                // добавить список сертификатов в список
                list.add(new X509Crl(provider, crl)); 
            }
        }
        // раскодировать отдельный список
        catch (IOException e) { list.add(engineGenerateCRL(encoded)); } return list;  
	}
	@Override
	public final CRL engineGenerateCRL(InputStream stream) throws CRLException 
	{
        // выделить динамический буфер
        ByteArrayOutputStream memoryStream = new ByteArrayOutputStream(); 
        try { 
            // прочитать данные во вспомогательный буфер
            byte[] buffer = new byte[4096]; int cb = stream.read(buffer); 

            // до окончания потока
            while (cb == buffer.length)
            {
                // сохранить прочитанные данные
                memoryStream.write(buffer); cb = stream.read(buffer); 
            }
            // сохранить прочитанные данные
            memoryStream.write(buffer, 0, cb); 
        }
        // обработать возможную ошибку
        catch (IOException e) { throw new CRLException(e.getMessage()); }
        
        // раскодировать список отозванных сертификатов
        return engineGenerateCRL(memoryStream.toByteArray()); 
	}
	public final CRL engineGenerateCRL(byte[] encoded) throws CRLException 
    {
        try {
            // раскодировать отдельный список отозванных сертификатов
            aladdin.asn1.iso.pkix.CertificateList crl = 
                new aladdin.asn1.iso.pkix.CertificateList(Encodable.decode(encoded)); 
            
            // создать объект списка отозванных сертификатов
            return new X509Crl(provider, crl); 
        }
        // обработать возможную ошибку
        catch (IOException e) { throw new CRLException(e.getMessage()); }
	}
    
	@Override
    public final Iterator<String> engineGetCertPathEncodings() 
	{
        // выделить спиоск для строк
		List<String> encodings = new ArrayList<String>(); 
        
		// указать поддерживаемые форматы потоков данных
        encodings.add("PkiPath"); encodings.add("PKCS7");

		// вернуть список поддерживаемых форматов
		return Collections.unmodifiableList(encodings).iterator();
    }
	@Override
    public final X509CertPath engineGenerateCertPath(InputStream stream,
        String encoding) throws CertificateException
    {
        // указать тип кодирования по умолчанию
		if (encoding == null) encoding = "PkiPath"; 
            
		// проверить поддержку формата
        if (!encoding.equals("PkiPath") && !encoding.equals("PKCS7")) 
        {
            // при ошибке выбросить исключение
            throw new CertificateException(); 
        }
        // выделить динамический буфер
        ByteArrayOutputStream memoryStream = new ByteArrayOutputStream(); 
        try { 
            // прочитать данные во вспомогательный буфер
            byte[] buffer = new byte[4096]; int cb = stream.read(buffer); 

            // до окончания потока
            while (cb == buffer.length)
            {
                // сохранить прочитанные данные
                memoryStream.write(buffer); cb = stream.read(buffer); 
            }
            // сохранить прочитанные данные
            memoryStream.write(buffer, 0, cb); 
        }
        // обработать возможную ошибку
        catch (IOException e) { throw new CertificateException(e.getMessage()); }
        
		// раскодировать сертификаты
		return engineGenerateCertPath(memoryStream.toByteArray(), encoding); 
    }
    public final X509CertPath engineGenerateCertPath(byte[] encoded,
        String encoding) throws CertificateException
    {
        // указать тип кодирования по умолчанию
		if (encoding == null) encoding = "PkiPath"; 
            
		// в зависимости от типа кодирования
        if (encoding.equals("PkiPath")) 
        try {
            // раскодировать данные
            Sequence<aladdin.asn1.iso.pkix.Certificate> certificates = 
                new Sequence<aladdin.asn1.iso.pkix.Certificate>(
                    aladdin.asn1.iso.pkix.Certificate.class, Encodable.decode(encoded));

            // создать список сертификатов
            X509Certificate[] list = new X509Certificate[certificates.size()]; 
            
            // для каждого сертификата
            for (int i = 0; i < certificates.size(); i++)
            {
                // добавить сертификат в список
                list[i] = new aladdin.capi.Certificate(certificates.get(i));
            }
            // вернуть цепочку сертификатов
            return new X509CertPath(list); 
        }
        // обработать возможное исключение
        catch (IOException e) { throw new CertificateException(e.getMessage()); }
        
        else if (encoding.equals("PKCS7"))    
        {
       		// создать список сертификатов
            List<java.security.cert.Certificate> list = 
                new ArrayList<java.security.cert.Certificate>(); 
            try {
                // раскодировать подписанные данные
                SignedData signedData = new SignedData(Encodable.decode(encoded)); 
            
                // для всех сертификатов из списка
                for (IEncodable encodable : signedData.certificates())
                {
                    // проверить наличие сертификата X.509
                    if (encodable.tag().equals(Tag.SEQUENCE)) continue; 
                
                    // добавить сертификат в список
                    list.add(new aladdin.capi.Certificate(encodable.encoded())); 
                }
            }
            // обработать возможное исключение
            catch (IOException e) { throw new CertificateException(e.getMessage()); }

            // упорядочить сертификаты
            return engineGenerateCertPath(list); 
        }
        // при ошибке выбросить исключение
        else throw new CertificateException(); 
    }
	@Override
    public final X509CertPath engineGenerateCertPath(InputStream stream) 
        throws CertificateException 
    {
        // раскодировать цепочку сертификатов
        return engineGenerateCertPath(stream, null); 
	}
	@Override
    public final X509CertPath engineGenerateCertPath(List<? extends Certificate> certificates)
        throws CertificateException
    {
/*        
		// создать список сертификатов
		super("X.509"); List<X509Certificate> list = new ArrayList<X509Certificate>(); 
		
		// для всех сертификатов из списка
		for (aladdin.x509.asn1.Certificate cert : certificates)
		{
			// раскодировать сертификат
			list.add(new X509Certificate(provider, cert));
		}
		// раскодировать сертификат
		X509Certificate subjectCertificate = new X509Certificate(provider, certificate); 
		
		// добавить сертификат в список
		this.certificates.add(subjectCertificate); list.remove(subjectCertificate); 
		
		// до окончания списка
		while (list.size() > 0)
		{
			// проверить идентификатор ключа издателя сертификата
			byte[] issuerKeyID = subjectCertificate.getIssuerKeyID(); if (issuerKeyID != null)
			{
				// проверить на самоподписанность
				if (subjectCertificate.isSubject(issuerKeyID)) return; 
				
				// для всех сертификатов из списка
				X509Certificate cert = null; for (X509Certificate other : list)
				{
					// проигнорировать самого себя
					if (other.equals(subjectCertificate)) continue; 
					
					// проверить идентификатор сертификата
					if (other.isSubject(issuerKeyID)) { cert = other; break; }
				}
				// переустановить начальные условия
				if (cert == null) return; subjectCertificate = cert; 
			}
			else {
				// определить имя издателя
				X500Principal issuer = subjectCertificate.getIssuerX500Principal(); 

				// проверить на самоподписанность
				if (issuer.equals(subjectCertificate.getSubjectX500Principal())) return;
				
				// для всех сертификатов из списка
				X509Certificate cert = null; for (X509Certificate other : list)
				{
					// проигнорировать самого себя
					if (other.equals(subjectCertificate)) continue; 
					
					// проверить идентификатор сертификата
					if (other.getSubjectX500Principal().equals(issuer)) { cert = other; break; }
				}
				// переустановить начальные условия
				if (cert == null) return; subjectCertificate = cert; 
			}
			// добавить сертификат в список
			this.certificates.add(subjectCertificate); list.remove(subjectCertificate);
		}
*/      return null; 
    }
}
