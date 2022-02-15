package aladdin.asn1.iso;
import aladdin.asn1.*; 
import java.io.*;

//	AlgorithmIdentifier  ::=  SEQUENCE  {
//		algorithm  OBJECT IDENTIFIER,
//		parameters ANY DEFINED BY algorithm OPTIONAL  
//	}

public final class AlgorithmIdentifier extends Sequence<IEncodable>
{
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(ObjectIdentifier.class).factory(), Cast.N), 
		new ObjectInfo(    ImplicitCreator				        .factory  , Cast.O), 
	};
	// конструктор при раскодировании
	public AlgorithmIdentifier(IEncodable encodable) throws IOException 
	{
		super(encodable, info); if (get(1) == null) return; 
		
		// установить пустой параметр
		if (get(1).content().length == 0) put(1, new Null(get(1)));
	}
	// конструктор при закодировании
	public AlgorithmIdentifier(ObjectIdentifier algorithm, IEncodable parameters) 
	{
		super(info, algorithm, parameters); 
	}
	public final ObjectIdentifier algorithm () { return (ObjectIdentifier)get(0); } 
	public final IEncodable		  parameters() { return                   get(1); }
}
