using System;

// ValidationParms ::= SEQUENCE {
//		seed            BIT STRING,
//		pgenCounter     INTEGER 
// }

namespace Aladdin.ASN1.ANSI.X957
{
	public class ValidationParms : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<BitString>().Factory(), Cast.N), 
			new ObjectInfo(new ObjectCreator<Integer  >().Factory(), Cast.N), 
		}; 
		// конструктор при раскодировании
		public ValidationParms(IEncodable encodable) : base(encodable, info) {}

		// конструктор при закодировании
		public ValidationParms(BitString seed, Integer counter) : 
			base(info, seed, counter) {}

		public BitString Seed	 { get { return (BitString)this[0]; } } 
		public Integer	 Counter { get { return (Integer  )this[1]; } }

        ////////////////////////////////////////////////////////////////////////////
        // Именованные наборы параметров
        ////////////////////////////////////////////////////////////////////////////
	    private static readonly ASN1.BitString Seed_Ephemeral = 
            new ASN1.BitString(new byte[] {
		    (byte)0x6c, (byte)0x33, (byte)0x72, (byte)0x3a, 
            (byte)0x27, (byte)0x16, (byte)0x72, (byte)0x0c,
		    (byte)0x14, (byte)0x96, (byte)0xaf, (byte)0x26, 
            (byte)0xc1, (byte)0xbe, (byte)0xa4, (byte)0x28, 
		    (byte)0x7b, (byte)0xe4, (byte)0x85, (byte)0x4e, 
	    });
	    private static readonly Integer Counter_Ephemeral = new Integer(165); 

	    // экземпляр параметров
	    public static readonly ValidationParms Ephemeral = 
            new ValidationParms(Seed_Ephemeral, Counter_Ephemeral); 
    }
}
