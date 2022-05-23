using System;
using System.Runtime.Serialization;

// ValidationParms ::= SEQUENCE {
//		seed            BIT STRING,
//		pgenCounter     INTEGER 
// }

namespace Aladdin.ASN1.ANSI.X957
{
	[Serializable]
	public class ValidationParms : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<BitString>().Factory(), Cast.N), 
			new ObjectInfo(new ObjectCreator<Integer  >().Factory(), Cast.N), 
		}; 
		// конструктор при сериализации
        protected ValidationParms(SerializationInfo info, StreamingContext context) : base(info, context) {}

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
	    private static readonly BitString Ephemeral_Seed = 
            new BitString(new byte[] {
		    (byte)0x6c, (byte)0x33, (byte)0x72, (byte)0x3a, 
            (byte)0x27, (byte)0x16, (byte)0x72, (byte)0x0c,
		    (byte)0x14, (byte)0x96, (byte)0xaf, (byte)0x26, 
            (byte)0xc1, (byte)0xbe, (byte)0xa4, (byte)0x28, 
		    (byte)0x7b, (byte)0xe4, (byte)0x85, (byte)0x4e, 
	    });
	    private static readonly Integer Ephemeral_Counter = new Integer(165); 

	    // экземпляр параметров
	    public static readonly ValidationParms Ephemeral = 
            new ValidationParms(Ephemeral_Seed, Ephemeral_Counter); 

	    private static readonly BitString JCA_Seed512 = 
            new BitString(new byte[] {
				0xb8, 0x69, 0xc8, 0x2b, 0x35, 0xd7, 0x0e, 0x1b, 
				0x1f, 0xf9, 0x1b, 0x28, 0xe3, 0x7a, 0x62, 0xec, 
				0xdc, 0x34, 0x40, 0x9b
		});
	    private static readonly Integer JCA_Counter512 = new Integer(123); 

	    // экземпляр параметров
	    public static readonly ValidationParms JCA512 = 
            new ValidationParms(JCA_Seed512, JCA_Counter512); 

	    private static readonly BitString JCA_Seed768 = 
            new BitString(new byte[] {
				0x77, 0xd0, 0xf8, 0xc4, 0xda, 0xd1, 0x5e, 0xb8, 
				0xc4, 0xf2, 0xf8, 0xd6, 0x72, 0x6c, 0xef, 0xd9, 
				0x6d, 0x5b, 0xb3, 0x99
		});
	    private static readonly Integer JCA_Counter768 = new Integer(263); 

	    // экземпляр параметров
	    public static readonly ValidationParms JCA768 = 
            new ValidationParms(JCA_Seed768, JCA_Counter768); 

	    private static readonly BitString JCA_Seed1024 = 
            new BitString(new byte[] {
				0x8d, 0x51, 0x55, 0x89, 0x42, 0x29, 0xd5, 0xe6, 
				0x89, 0xee, 0x01, 0xe6, 0x01, 0x8a, 0x23, 0x7e, 
				0x2c, 0xae, 0x64, 0xcd
		});
	    private static readonly Integer JCA_Counter1024 = new Integer(92); 

	    // экземпляр параметров
	    public static readonly ValidationParms JCA1024 = 
            new ValidationParms(JCA_Seed1024, JCA_Counter1024); 
    }
}
