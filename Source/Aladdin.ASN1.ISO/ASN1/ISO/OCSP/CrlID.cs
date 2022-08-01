using System;
using System.Runtime.Serialization;

// CrlID ::= SEQUENCE {
//		crlUrl  [0] EXPLICIT IA5String OPTIONAL,
//		crlNum  [1] EXPLICIT INTEGER OPTIONAL,
//		crlTime [2] EXPLICIT GeneralizedTime OPTIONAL
// }

namespace Aladdin.ASN1.ISO.OCSP
{
	[Serializable]
	public class CrlID : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<IA5String      >().Factory(), Cast.EO, Tag.Context(0)), 
			new ObjectInfo(new ObjectCreator<Integer		>().Factory(), Cast.EO, Tag.Context(1)), 
			new ObjectInfo(new ObjectCreator<GeneralizedTime>().Factory(), Cast.EO, Tag.Context(2)) 
		}; 
		// конструктор при сериализации
        protected CrlID(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public CrlID(IEncodable encodable) : base(encodable, info) {} 

		// конструктор при закодировании
		public CrlID(IA5String crlUrl, Integer crlNum, GeneralizedTime crlTime) : 
			base(info, crlUrl, crlNum, crlTime) {} 

		public IA5String		CrlUrl	{ get { return (IA5String		)this[0]; } } 
		public Integer			CrlNum	{ get { return (Integer			)this[1]; } }
		public GeneralizedTime	CrlTime	{ get { return (GeneralizedTime	)this[2]; } }
	}
}
