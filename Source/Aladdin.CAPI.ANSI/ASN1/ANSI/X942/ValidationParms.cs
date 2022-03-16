using System;
using System.Runtime.Serialization;

// ValidationParms ::= SEQUENCE {
//		seed            BIT STRING,
//		pgenCounter     INTEGER 
// }

namespace Aladdin.ASN1.ANSI.X942
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
	}
}
