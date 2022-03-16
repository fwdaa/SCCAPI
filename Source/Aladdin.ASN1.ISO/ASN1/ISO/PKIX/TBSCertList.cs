using System;
using System.Runtime.Serialization;

//	TBSCertList  ::=  SEQUENCE  {
//		version							 INTEGER				OPTIONAL,
//		signature						 AlgorithmIdentifier,
//		issuer							 Name,
//		thisUpdate						 Time,
//		nextUpdate						 Time					OPTIONAL,
//		revokedCertificates				 RevokedCertificates	OPTIONAL,
//		crlExtensions       [0] EXPLICIT Extensions				OPTIONAL 
//	}

namespace Aladdin.ASN1.ISO.PKIX
{
	[Serializable]
	public class TBSCertList : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<Integer			>().Factory(), Cast.O,	Tag.Any			), 
			new ObjectInfo(new ObjectCreator<AlgorithmIdentifier>().Factory(), Cast.N,	Tag.Any			), 
			new ObjectInfo(new ChoiceCreator<Name				>().Factory(), Cast.N,	Tag.Any			), 
			new ObjectInfo(new ChoiceCreator<Time				>().Factory(), Cast.N,	Tag.Any			), 
			new ObjectInfo(new ChoiceCreator<Time				>().Factory(), Cast.O,	Tag.Any			), 
			new ObjectInfo(new ObjectCreator<RevokedCertificates>().Factory(), Cast.O,	Tag.Any			), 
			new ObjectInfo(new ObjectCreator<Extensions			>().Factory(), Cast.EO,	Tag.Context(0)	), 
		}; 
		// конструктор при сериализации
        protected TBSCertList(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public TBSCertList(IEncodable encodable) : base(encodable, info) {}

		// конструктор при закодировании
		public TBSCertList(Integer version, AlgorithmIdentifier signature, IEncodable issuer,	
			VisibleString thisUpdate, VisibleString nextUpdate, RevokedCertificates revokedCertificates, 
			Extensions attributes) : base(info, version, signature, issuer, thisUpdate, 
			nextUpdate, revokedCertificates, attributes) {}

		public Integer				Version				{ get { return (Integer				)this[0]; } } 
		public AlgorithmIdentifier	Signature			{ get { return (AlgorithmIdentifier	)this[1]; } }
		public IEncodable			Issuer				{ get { return						 this[2]; } }
		public VisibleString		ThisUpdate			{ get { return (VisibleString		)this[3]; } }
		public VisibleString		NextUpdate			{ get { return (VisibleString		)this[4]; } }
		public RevokedCertificates	RevokedCertificates { get { return (RevokedCertificates	)this[5]; } }
		public Extensions			Attributes			{ get { return (Extensions			)this[6]; } }
	}
}
