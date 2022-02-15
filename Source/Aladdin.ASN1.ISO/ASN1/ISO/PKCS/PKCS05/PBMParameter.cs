using System;

//	PBMParameter ::= SEQUENCE {
//		salt                OCTET STRING,
//		owf                 AlgorithmIdentifier,
//		iterationCount      INTEGER,
//		mac                 AlgorithmIdentifier
//	}

namespace Aladdin.ASN1.ISO.PKCS.PKCS5
{
	public class PBMParameter : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<OctetString		>().Factory(), Cast.N), 
			new ObjectInfo(new ObjectCreator<AlgorithmIdentifier>().Factory(), Cast.N), 
			new ObjectInfo(new ObjectCreator<Integer			>().Factory(), Cast.N), 
			new ObjectInfo(new ObjectCreator<AlgorithmIdentifier>().Factory(), Cast.N), 
		}; 
		// конструктор при раскодировании
		public PBMParameter(IEncodable encodable) : base(encodable, info) {}

		// конструктор при закодировании
		public PBMParameter(OctetString salt, AlgorithmIdentifier owf, 
			Integer iterationCount, AlgorithmIdentifier mac) : 
			base(info, salt, owf, iterationCount, mac) {}

		public OctetString			Salt			{ get { return (OctetString			)this[0]; } } 
		public AlgorithmIdentifier	OWF				{ get { return (AlgorithmIdentifier	)this[1]; } } 
		public Integer				IterationCount	{ get { return (Integer				)this[2]; } }
		public AlgorithmIdentifier	MAC				{ get { return (AlgorithmIdentifier	)this[3]; } } 
	}
}
