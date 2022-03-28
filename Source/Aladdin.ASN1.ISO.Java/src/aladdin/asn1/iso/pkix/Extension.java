package aladdin.asn1.iso.pkix;
import aladdin.asn1.*; 
import aladdin.asn1.Boolean; 
import java.io.*; 

//	Extension  ::=  SEQUENCE  {
//		extnID      OBJECT IDENTIFIER,
//		critical    BOOLEAN DEFAULT FALSE,
//		extnValue   OCTET STRING
//	}

public final class Extension extends Sequence<IEncodable>
{
    private static final long serialVersionUID = 178351428137649005L;
    
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(ObjectIdentifier.class).factory(), Cast.N, Tag.ANY	 			    ), 
		new ObjectInfo(new ObjectCreator(Boolean         .class).factory(), Cast.O, Tag.ANY, Boolean.FALSE  ), 
		new ObjectInfo(new ObjectCreator(OctetString	 .class).factory(), Cast.N, Tag.ANY					), 
	}; 
	public Extension(IEncodable encodable) throws IOException
	{
        // инициализировать объект
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
        decoded = Encodable.decode(get(2).content()); 
    }
	// конструктор при закодировании
	public Extension(ObjectIdentifier extnID, Boolean critical, IEncodable extnValue) 
	{
		// раскодировать атрибут
		super(info, extnID, critical, new OctetString(extnValue.encoded())); decoded = extnValue; 
	}
	public final ObjectIdentifier	extnID  () { return (ObjectIdentifier)get(0); } 
	public final Boolean	        critical() { return (Boolean         )get(1); }

	// раскодированное значение атрибута
	public final IEncodable extnValue() { return decoded; } private IEncodable decoded; 
}
