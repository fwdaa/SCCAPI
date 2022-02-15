package aladdin.asn1.iso;
import aladdin.asn1.*; 
import java.io.*; 

//	OtherRevocationInfoFormat ::= SEQUENCE {
//		otherRevInfoFormat	OBJECT IDENTIFIER,
//		otherRevInfo		ANY DEFINED BY otherRevInfoFormat 
//	}

public final class OtherRevocationInfoFormat extends Sequence<IEncodable>
{
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(ObjectIdentifier.class).factory(), Cast.N), 
		new ObjectInfo(ImplicitCreator						    .factory  , Cast.N), 
	}; 
	// конструктор при раскодировании
	public OtherRevocationInfoFormat(IEncodable encodable) throws IOException { super(encodable, info); }

	// конструктор при закодировании
	public OtherRevocationInfoFormat(ObjectIdentifier otherRevInfoFormat, IEncodable otherRevInfo) 
	{
		super(info, otherRevInfoFormat, otherRevInfo); 
	}
	public final ObjectIdentifier otherRevInfoFormat() { return (ObjectIdentifier)get(0); } 
	public final IEncodable		  otherRevInfo	    () { return                   get(1); }
}
