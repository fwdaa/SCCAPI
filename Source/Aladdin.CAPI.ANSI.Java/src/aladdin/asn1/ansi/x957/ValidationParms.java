package aladdin.asn1.ansi.x957; 
import aladdin.asn1.*; 
import aladdin.asn1.Integer; 
import java.io.*; 

// ValidationParms ::= SEQUENCE {
//		seed            BIT STRING,
//		pgenCounter     INTEGER 
// }

public final class ValidationParms extends Sequence<IEncodable>
{
    private static final long serialVersionUID = 7694887962411797851L;
    
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

        new ObjectInfo(new ObjectCreator(BitString.class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(Integer  .class).factory(), Cast.N) 
	}; 
	// конструктор при раскодировании
	public ValidationParms(IEncodable encodable) throws IOException { super(encodable, info); }

	// конструктор при закодировании
	public ValidationParms(BitString seed, Integer counter) { super(info, seed, counter); }

	public final BitString seed   () { return (BitString)get(0); } 
	public final Integer   counter() { return (Integer  )get(1); }

    ////////////////////////////////////////////////////////////////////////////
    // Именованные наборы параметров
    ////////////////////////////////////////////////////////////////////////////
	private static final BitString SEED_EPHEMERAL = new BitString(new byte[] {
		(byte)0x6c, (byte)0x33, (byte)0x72, (byte)0x3a, 
        (byte)0x27, (byte)0x16, (byte)0x72, (byte)0x0c,
		(byte)0x14, (byte)0x96, (byte)0xaf, (byte)0x26, 
        (byte)0xc1, (byte)0xbe, (byte)0xa4, (byte)0x28, 
		(byte)0x7b, (byte)0xe4, (byte)0x85, (byte)0x4e, 
	});
	private static final Integer COUNTER_EPHEMERAL = new Integer(165); 

	// экземпляр параметров
	public static final ValidationParms EPHEMERAL = 
        new ValidationParms(SEED_EPHEMERAL, COUNTER_EPHEMERAL); 
}
