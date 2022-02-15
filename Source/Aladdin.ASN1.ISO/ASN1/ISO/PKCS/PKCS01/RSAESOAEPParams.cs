using System;

//	RSAES-OAEP-params ::= SEQUENCE {
//		hashAlgorithm      [0] EXPLICIT AlgorithmIdentifier DEFAULT sha1,
//		maskGenAlgorithm   [1] EXPLICIT AlgorithmIdentifier DEFAULT mgf1SHA1,
//		pSourceAlgorithm   [2] EXPLICIT AlgorithmIdentifier DEFAULT pSpecifiedEmpty
//	}

namespace Aladdin.ASN1.ISO.PKCS.PKCS1
{
	public class RSAESOAEPParams : Sequence
	{
		// значение по умолчанию
		private static readonly OctetString empty = new OctetString(new byte[0]); 

		// значение по умолчанию
		private static readonly AlgorithmIdentifier sha1 = 
			new AlgorithmIdentifier(new ObjectIdentifier("1.3.14.3.2.26"), Null.Instance);

		// значение по умолчанию
		private static readonly AlgorithmIdentifier mgf1_sha1 = 
			new AlgorithmIdentifier(new ObjectIdentifier(OID.rsa_mgf1), sha1); 

		// значение по умолчанию
		private static readonly AlgorithmIdentifier pSpecifiedEmpty = 
			new AlgorithmIdentifier(new ObjectIdentifier(OID.rsa_specified), empty); 
 
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<AlgorithmIdentifier>().Factory(), Cast.EO, Tag.Context(0), sha1			), 
			new ObjectInfo(new ObjectCreator<AlgorithmIdentifier>().Factory(), Cast.EO, Tag.Context(1), mgf1_sha1		), 
			new ObjectInfo(new ObjectCreator<AlgorithmIdentifier>().Factory(), Cast.EO, Tag.Context(2), pSpecifiedEmpty	), 
		}; 
		// конструктор при раскодировании
		public RSAESOAEPParams(IEncodable encodable) : base(encodable, info) {}

		// конструктор при закодировании
		public RSAESOAEPParams(AlgorithmIdentifier hashAlgorithm, AlgorithmIdentifier maskGenAlgorithm, 
			AlgorithmIdentifier pSourceAlgorithm) : base(info, hashAlgorithm, maskGenAlgorithm, pSourceAlgorithm) {}

		public AlgorithmIdentifier	HashAlgorithm		{ get { return (AlgorithmIdentifier)this[0]; } } 
		public AlgorithmIdentifier	MaskGenAlgorithm	{ get { return (AlgorithmIdentifier)this[1]; } }
		public AlgorithmIdentifier	PSourceAlgorithm	{ get { return (AlgorithmIdentifier)this[2]; } }
		public OctetString			Label				{ get 
		{
			// проверить тип метки
			if (PSourceAlgorithm.Algorithm.Value != OID.rsa_specified) return empty;
			
			// получить значение метки
			return new OctetString(PSourceAlgorithm.Parameters); 
		}}
	}
}
