package aladdin.asn1.iso.pkix;
import aladdin.asn1.*; 
import aladdin.asn1.Set; 
import aladdin.asn1.iso.*; 
import aladdin.asn1.iso.pkix.ce.*;
import java.io.*; 
import java.util.*; 

// Extensions ::= SEQUENCE OF Extension

public final class Extensions extends Sequence<Extension>
{
	// конструктор при раскодировании
	public Extensions(IEncodable encodable) throws IOException
	{ 
		super(Extension.class, encodable); 
	}; 
	// конструктор при закодировании
	public Extensions(Extension... values) 
	{
		super(Extension.class, values); 
	}
	// конструктор при закодировании
	public Extensions(Attribute attribute) 
	{
		super(Extension.class, extractExtensions(attribute));
	} 
	private static Extension[] extractExtensions(Attribute attribute) 
	{
		// создать пустой список расширений
		List<Extension> extensions = new ArrayList<Extension>(); 
		try { 
			// извлечь расширения для сертификата
			Set<Extensions> setExtensions = new Set<Extensions>(
                Extensions.class, attribute.values()
            ); 
			// добавить расширения в список
			for (Extensions exts : setExtensions) 
			{
				// добавить расширения в список
				for (Extension ext : exts) extensions.add(ext);
			} 
			// вернуть расширения из атрибута
			return extensions.toArray(new Extension[0]); 
		}
		catch (IOException e) { throw new IllegalArgumentException(); }
	}
	public final IEncodable get(String oid) 
	{
		// для всех параметров
		for (Extension extension : this)
		{
			// проверить совпадение идентификатора
			if (extension.extnID().value().equals(oid)) return extension.extnValue(); 		
		}
		return null; 
	}
    public OctetString subjectKeyIdentifier() throws IOException   
    {
        // получить расширение
        IEncodable value = get(OID.CE_SUBJECT_KEY_IDENTIFIER); 

        // раскодировать расширение
        return (value != null) ? new OctetString(value) : null; 
    }
    public AuthorityKeyIdentifier authorityKeyIdentifier() throws IOException
    {
        // получить расширение
        IEncodable value = get(OID.CE_AUTHORITY_KEY_IDENTIFIER); 

        // раскодировать расширение
        if (value != null) return new AuthorityKeyIdentifier(value); 
        
        // получить расширение
        value = get(OID.CE_AUTHORITY_KEY_IDENTIFIER_OLD); if (value != null)
        {
            // выполнить преобразование типа
            return new AuthorityKeyIdentifierOld(value).update(); 
        }
        return null; 
    }
    public long keyUsage() throws IOException
    {
        // получить расширение
        IEncodable value = get(OID.CE_KEY_USAGE); 

        // проверить наличие расширения
        if (value == null) return KeyUsage.NONE;
            
        // раскодировать расширение
        BitFlags flags = new BitFlags(value); return flags.flags(); 
    }
    public ExtKeyUsageSyntax extendedKeyUsage() throws IOException
    {
        // получить расширение
        IEncodable value = get(OID.CE_EXT_KEY_USAGE); 

        // раскодировать расширение
        return (value != null) ? new ExtKeyUsageSyntax(value) : null; 
    }
    public BasicConstraints basicConstraints() throws IOException
    {
        // получить расширение
        IEncodable value = get(OID.CE_BASIC_CONSTRAINTS); 

        // раскодировать расширение
        return (value != null) ? new BasicConstraints(value) : null; 
    }
    public CertificatePolicies certificatePolicies() throws IOException
    {
        // получить расширение
        IEncodable value = get(OID.CE_CERIFICATE_POLICIES); 

        // раскодировать расширение
        return (value != null) ? new CertificatePolicies(value) : null; 
    }
}
