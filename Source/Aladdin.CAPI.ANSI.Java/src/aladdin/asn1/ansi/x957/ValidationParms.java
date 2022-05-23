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
	private static final BitString EPHEMERAL_SEED = new BitString(new byte[] {
		(byte)0x6c, (byte)0x33, (byte)0x72, (byte)0x3a, 
        (byte)0x27, (byte)0x16, (byte)0x72, (byte)0x0c,
		(byte)0x14, (byte)0x96, (byte)0xaf, (byte)0x26, 
        (byte)0xc1, (byte)0xbe, (byte)0xa4, (byte)0x28, 
		(byte)0x7b, (byte)0xe4, (byte)0x85, (byte)0x4e, 
	});
	private static final Integer EPHEMERAL_COUNTER = new Integer(165); 

	// экземпляр параметров
	public static final ValidationParms EPHEMERAL = 
        new ValidationParms(EPHEMERAL_SEED, EPHEMERAL_COUNTER); 
    
	private static final BitString JCA_SEED512 = 
        new BitString(new byte[] {
            (byte)0xb8, (byte)0x69, (byte)0xc8, (byte)0x2b, 
            (byte)0x35, (byte)0xd7, (byte)0x0e, (byte)0x1b, 
			(byte)0x1f, (byte)0xf9, (byte)0x1b, (byte)0x28, 
            (byte)0xe3, (byte)0x7a, (byte)0x62, (byte)0xec, 
			(byte)0xdc, (byte)0x34, (byte)0x40, (byte)0x9b
	});
	private static final Integer JCA_COUNTER512 = new Integer(123); 

	// экземпляр параметров
	public static final ValidationParms JCA512 = 
        new ValidationParms(JCA_SEED512, JCA_COUNTER512); 

	private static final BitString JCA_SEED768 = 
        new BitString(new byte[] {
			(byte)0x77, (byte)0xd0, (byte)0xf8, (byte)0xc4, 
            (byte)0xda, (byte)0xd1, (byte)0x5e, (byte)0xb8, 
			(byte)0xc4, (byte)0xf2, (byte)0xf8, (byte)0xd6, 
            (byte)0x72, (byte)0x6c, (byte)0xef, (byte)0xd9, 
			(byte)0x6d, (byte)0x5b, (byte)0xb3, (byte)0x99
	});
	private static final Integer JCA_COUNTER768 = new Integer(263); 

	// экземпляр параметров
	public static final ValidationParms JCA768 = 
        new ValidationParms(JCA_SEED768, JCA_COUNTER768); 

	private static final BitString JCA_SEED1024 = 
        new BitString(new byte[] {
			(byte)0x8d, (byte)0x51, (byte)0x55, (byte)0x89, 
            (byte)0x42, (byte)0x29, (byte)0xd5, (byte)0xe6, 
			(byte)0x89, (byte)0xee, (byte)0x01, (byte)0xe6, 
            (byte)0x01, (byte)0x8a, (byte)0x23, (byte)0x7e, 
			(byte)0x2c, (byte)0xae, (byte)0x64, (byte)0xcd
	});
	private static final Integer JCA_COUNTER1024 = new Integer(92); 

	// экземпляр параметров
	public static final ValidationParms JCA1024 = 
        new ValidationParms(JCA_SEED1024, JCA_COUNTER1024); 
}
