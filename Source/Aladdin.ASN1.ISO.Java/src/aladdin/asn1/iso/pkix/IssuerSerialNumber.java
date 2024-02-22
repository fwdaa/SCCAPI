package aladdin.asn1.iso.pkix;
import aladdin.asn1.*; 
import aladdin.asn1.Integer; 
import java.io.*; 

//	IssuerSerialNumber ::= SEQUENCE {
//		issuer			Name,
//		serialNumber	INTEGER 
//	}

public final class IssuerSerialNumber extends Sequence<IEncodable>
{
    private static final long serialVersionUID = -765807028901536567L;
    
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ChoiceCreator(Name     .class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(Integer  .class).factory(), Cast.N), 
	}; 
	// конструктор при раскодировании
	public IssuerSerialNumber(IEncodable encodable) throws IOException { super(encodable, info); }

	// конструктор при закодировании
	public IssuerSerialNumber(IEncodable issuer, Integer serialNumber) 
	{
		super(info, issuer, serialNumber); 
	}
	public final IEncodable	issuer	    () { return		     get(0); } 
	public final Integer    serialNumber() { return (Integer)get(1); }
}
