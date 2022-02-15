package aladdin.capi;
import aladdin.asn1.*; 
import aladdin.asn1.iso.*; 
import aladdin.asn1.iso.pkix.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Запрос на сертификат X509
///////////////////////////////////////////////////////////////////////////
public class CertificateRequest
{
	///////////////////////////////////////////////////////////////////////
	// Конструкторы
	///////////////////////////////////////////////////////////////////////
	public CertificateRequest(InputStream stream) throws IOException
    {
        // прочитать первый символ
        int first = stream.read(); if (first < 0) throw new IOException(); 
        
        // для PEM-кодировки
        if (first == 0x2D) { byte[] encoded = PEM.decode(stream, (byte)first);
        
            // раскодировать сертификат
            IEncodable encodable = Encodable.decode(encoded); 
        
            // сохранить содержимое запроса на сертификат
            this.request = new aladdin.asn1.iso.pkcs.pkcs10.CertificationRequest(encodable); 
        }
        else {
            // раскодировать сертификат
            IEncodable encodable = Encodable.decode(stream, (byte)first); 
        
            // сохранить содержимое сертификата
            this.request = new aladdin.asn1.iso.pkcs.pkcs10.CertificationRequest(encodable); 
        }
    }
	public CertificateRequest(byte[] encoded) throws IOException
    {
        // обработать PEM-кодировку
        if (encoded.length != 0 && encoded[0] == 0x2D) encoded = PEM.decode(encoded);
        
        // раскодировать запрос на сертификат
        IEncodable encodable = Encodable.decode(encoded); 
        
        // сохранить запрос на сертификат
        this.request = new aladdin.asn1.iso.pkcs.pkcs10.CertificationRequest(encodable); 
    }
	public CertificateRequest(aladdin.asn1.iso.pkcs.pkcs10.CertificationRequest request) 
    {
		// раскодировать запрос на сертификат
		this.request = request; 
    }
    // раскодированный запрос на сертификат
	private final aladdin.asn1.iso.pkcs.pkcs10.CertificationRequest request;		
    
    // раскодированный запрос на сертификат
    public aladdin.asn1.iso.pkcs.pkcs10.CertificationRequest decoded() { return request; }
    
	///////////////////////////////////////////////////////////////////////
	// Методы Object
	///////////////////////////////////////////////////////////////////////
	public boolean equals(CertificateRequest other)
	{
		// проверить совпадение сертификатов
		return request.equals(other.request); 
	}
	// сравнение сертификатов
	@Override public boolean equals(java.lang.Object obj)
	{
        // сравнить сертификаты
        return (obj instanceof CertificateRequest) && equals((CertificateRequest)obj); 
	}
	// получить хэш-код объекта
	@Override public int hashCode() { return request.hashCode(); }
    
	///////////////////////////////////////////////////////////////////////
    // Закодированное представление
	///////////////////////////////////////////////////////////////////////
    public byte[] der() { return request.encoded(); }
    public String pem()  
    {
        // закодировать запрос на сертификат
        return PEM.encode(getEncoded(), "CERTIFICATE REQUEST"); 
    }
    // закодированное представление 
    public byte[] getEncoded() { return request.encoded(); }
    
    ///////////////////////////////////////////////////////////////////////
    // Подпись запроса на сертификат
    ///////////////////////////////////////////////////////////////////////
    public byte[] getTBSCertificateRequest()
    {
        // подписываемая часть запроса на сертификат
        return request.certificationRequestInfo().encoded(); 
    }
	public AlgorithmIdentifier signatureAlgorithm() 
    { 
        // описание алгоритма подписи
        return request.signatureAlgorithm();    
    }
    // идентификатор алгоритма подписи
    public String getSigAlgName() { return getSigAlgOID(); }
    public String getSigAlgOID ()
    {
        // получить описание алгоритма подписи
        AlgorithmIdentifier algorithm = signatureAlgorithm(); 
        
        // идентификатор алгоритма подписи
        return algorithm.algorithm().value(); 
    }
    public byte[] getSigAlgParams()
    {
        // получить описание алгоритма подписи
        AlgorithmIdentifier algorithm = signatureAlgorithm(); 
        
        // проверить наличие параметров
        if (algorithm.parameters() == null) return null; 
        
        // вернуть параметры алгоритма подписи
        return algorithm.parameters().encoded(); 
    }
    // подпись сертификата
    public byte[] getSignature() { return signature().value(); } 
    
    // подпись сертификата
	public BitString signature() { return request.signature(); }
    
	///////////////////////////////////////////////////////////////////////
	// Открытый ключ запроса на сертификат
	///////////////////////////////////////////////////////////////////////
	public IPublicKey getPublicKey(Factory factory) throws IOException
    { 
        // раскодировать открытый ключ
        return factory.decodePublicKey(publicKeyInfo()); 
    }
    // открытый ключ сертификата
    public java.security.PublicKey getPublicKey()
    {
        // открытый ключ запроса на сертификат
        return new Certificate.PublicKey(publicKeyInfo()); 
    }
	public SubjectPublicKeyInfo	publicKeyInfo() 
    { 
        // закодированный открытый ключ запроса на сертификат
        return request.certificationRequestInfo().subjectPKInfo();         
    }
    ///////////////////////////////////////////////////////////////////////
    // Атрибуты запроса на сертификат
    ///////////////////////////////////////////////////////////////////////
    public int getVersion()
    {
        // версия запроса на сертификат
        return request.certificationRequestInfo().version().value().intValue(); 
    }
    // субъект запроса на сертификат
	public IEncodable subject() { return request.certificationRequestInfo().subject(); }
    
    // атрибуты запроса на сертификат
	public Attributes attributes() 
    { 
        // атрибуты запроса на сертификат
        return request.certificationRequestInfo().attributes();                  
    } 
    ///////////////////////////////////////////////////////////////////////
    // Расширения запроса на сертификат
    ///////////////////////////////////////////////////////////////////////
	public Extensions extensions() 
    { 
		// для всех атрибутов запроса
        for (Attribute attribute : attributes())
		{
			// для атрибутов расширений
			if (attribute.type().value().equals(aladdin.asn1.iso.pkcs.pkcs9.OID.EXTENSION_REQUEST))
			{
				// извлечь расширения для сертификата
				return new Extensions(attribute);
			}
		}
        return null;                         
    }
    // способ использования ключа
	public KeyUsage keyUsage() 
    { 
        // получить расширения запроса на сертификат
        Extensions extensions = extensions(); if (extensions == null) return KeyUsage.NONE;
        try {    
            // вернуть способ использования ключа
            return new KeyUsage(extensions.keyUsage());             
        }
        // обработать возможную ошибку
        catch (Throwable e) { return KeyUsage.NONE; }
    }
}
