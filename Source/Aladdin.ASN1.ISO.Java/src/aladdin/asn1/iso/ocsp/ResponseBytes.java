package aladdin.asn1.iso.ocsp;
import aladdin.asn1.*;
import java.io.*;

// ResponseBytes ::= SEQUENCE {
//     responseType  RESPONSE.&id ({ResponseSet}),
//     response      OCTET STRING (CONTAINING RESPONSE.&Type({ResponseSet}{@responseType}))
// }

public class ResponseBytes extends Sequence<IEncodable>
{
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(ObjectIdentifier.class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(OctetString     .class).factory(), Cast.N) 
	}; 
	// конструктор при раскодировании
	public ResponseBytes(IEncodable encodable) throws IOException 
    { 
        super(encodable, info); init(); 
    }
    // сериализация
    @Override protected void readObject(ObjectInputStream ois) throws IOException 
    {
        // прочитать объект
        super.readObject(ois); init(); 
    }    
    // инициализировать объект
    private void init() throws IOException
    {
        // раскодировать объект
        decoded = Encodable.decode(get(1).content()); 
    }
	// конструктор при закодировании
	public ResponseBytes(ObjectIdentifier responseType, IEncodable response) 
	{ 
		super(info, responseType, new OctetString(response.encoded())); decoded = response; 
	}
	public final ObjectIdentifier responseType() { return (ObjectIdentifier)get(0); } 
    
	// раскодированное значение атрибута
	public final IEncodable response() { return decoded; } private IEncodable decoded; 
}
