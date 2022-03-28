package aladdin.asn1.iso.pkix.ce;
import aladdin.asn1.*; 
import aladdin.asn1.Integer; 
import aladdin.asn1.iso.pkix.*; 
import java.io.*; 

//	AuthorityKeyIdentifierOld ::= SEQUENCE {
//		keyIdentifier             [0] IMPLICIT OCTET STRING	OPTIONAL,
//		authorityCertIssuer       [1] IMPLICIT Name         OPTIONAL,
//		authorityCertSerialNumber [2] IMPLICIT INTEGER		OPTIONAL 
//	}

public final class AuthorityKeyIdentifierOld extends Sequence<IEncodable>
{
    private static final long serialVersionUID = 2379433824276032717L;
        
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(OctetString.class).factory(), Cast.O , Tag.context(0)), 
		new ObjectInfo(new ChoiceCreator(Name       .class).factory(), Cast.O,  Tag.context(1)), 
		new ObjectInfo(new ObjectCreator(Integer    .class).factory(), Cast.O , Tag.context(2)), 
	}; 
	// конструктор при раскодировании
	public AuthorityKeyIdentifierOld(IEncodable encodable) throws IOException { super(encodable, info); 
	
		// проверить наличие элементов
		if (authorityCertIssuer() == null && authorityCertSerialNumber() != null) throw new IOException(); 
		if (authorityCertIssuer() != null && authorityCertSerialNumber() == null) throw new IOException(); 
	}
	// конструктор при закодировании
	public AuthorityKeyIdentifierOld(OctetString keyIdentifier, IEncodable authorityCertIssuer, 
		Integer authorityCertSerialNumber) 
	{
		super(info, keyIdentifier, authorityCertIssuer, authorityCertSerialNumber); 
		
		// проверить наличие элементов
		if (authorityCertIssuer == null && authorityCertSerialNumber != null) throw new IllegalArgumentException(); 
		if (authorityCertIssuer != null && authorityCertSerialNumber == null) throw new IllegalArgumentException(); 
	}
	public final OctetString	keyIdentifier			 () { return (OctetString)get(0); } 
	public final IEncodable     authorityCertIssuer		 () { return              get(1); }
	public final Integer        authorityCertSerialNumber() { return (Integer    )get(2); }
    
    // выполнить преобразование типа
    public AuthorityKeyIdentifier update() 
    {
        // переопределить используемый тип
        IEncodable encodable = Explicit.encode(Tag.context(4), authorityCertIssuer()); 
            
        // указать издателя сертификата
        GeneralNames names = new GeneralNames(new IEncodable[] { encodable }); 
        
        // выполнить преобразование типа
        return new AuthorityKeyIdentifier(keyIdentifier(), names, authorityCertSerialNumber()); 
    }
}
