package aladdin.capi.jcp;
import aladdin.asn1.*; 
import java.security.cert.*;
import java.util.*;
import java.io.*;

///////////////////////////////////////////////////////////////////////////////
// Цепочка сертификатов X.509
///////////////////////////////////////////////////////////////////////////////
public final class X509CertPath extends java.security.cert.CertPath
{
    // номер версии при сериализации
    private static final long serialVersionUID = 3377829230130384598L;

    // список сертификатов
	private final List<X509Certificate> certificates; 
	
	// конструктор
	public X509CertPath(X509Certificate[] certificates) 
	{
		// создать список сертификатов
		super("X.509"); this.certificates = Arrays.asList(certificates); 
	}
	@Override
	public final List<? extends Certificate> getCertificates() { return certificates; }
	
	@Override
	public final Iterator<String> getEncodings() 
	{
		// поддерживаемые форматы потоков данных
		List<String> encodings = new ArrayList<String>(); encodings.add("PkiPath"); 

		// вернуть список поддерживаемых форматов
		return Collections.unmodifiableList(encodings).iterator();
	}
	@Override
	public final byte[] getEncoded() throws CertificateEncodingException 
	{
		// закодировать сертификаты по умолчанию
		return getEncoded("PkiPath"); 
	}
	@Override
	public final byte[] getEncoded(String encoding) throws CertificateEncodingException 
	{
        // указать тип кодирования по умолчанию
		if (encoding == null) encoding = "PkiPath"; 
            
		// проверить поддержку формата
        if (!encoding.equals("PkiPath")) throw new CertificateEncodingException();
        
		// создать список сертификатов
		aladdin.asn1.iso.pkix.Certificate[] certs = 
			new aladdin.asn1.iso.pkix.Certificate[certificates.size()]; 
		
        // для всех сертификатов
		for (int i = 0; i < certs.length; i++) 
        try {
            // указать закодированное представление
            certs[i] = new aladdin.asn1.iso.pkix.Certificate(
                Encodable.decode(certificates.get(i).getEncoded())
            ); 
        }
        // обработать возможное исключение
        catch (IOException e) { throw new CertificateEncodingException(); }
        
		// закодировать сертификаты
		return new Sequence<aladdin.asn1.iso.pkix.Certificate>(
            aladdin.asn1.iso.pkix.Certificate.class, certs).encoded(); 
	}
}
