using System;
using System.IO;
using System.Runtime.Serialization;

//	RSASSA-PSS-params ::= SEQUENCE {
//		hashAlgorithm      [0] HashAlgorithm      DEFAULT sha1,
//		maskGenAlgorithm   [1] MaskGenAlgorithm   DEFAULT mgf1SHA1,
//		saltLength         [2] INTEGER            DEFAULT 20,
//		trailerField       [3] TrailerField       DEFAULT trailerFieldBC
//	}
//  TrailerField ::= INTEGER { trailerFieldBC(1) }

namespace Aladdin.ASN1.ISO.PKCS.PKCS1
{
	[Serializable]
	public class RSASSAPSSParams : Sequence
	{
		// значение по умолчанию
		private static readonly AlgorithmIdentifier sha1 = 
			new AlgorithmIdentifier(new ObjectIdentifier("1.3.14.3.2.26"), Null.Instance);

		// значение по умолчанию
		private static readonly AlgorithmIdentifier mgf1_sha1 = 
			new AlgorithmIdentifier(new ObjectIdentifier(OID.rsa_mgf1), sha1); 

		// значение по умолчанию
		private static readonly Integer trailerFieldBC = new Integer(1); 
 
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<AlgorithmIdentifier	>().Factory(), Cast.EO, Tag.Context(0), sha1			), 
			new ObjectInfo(new ObjectCreator<AlgorithmIdentifier	>().Factory(), Cast.EO, Tag.Context(1), mgf1_sha1	    ), 
			new ObjectInfo(new ObjectCreator<Integer				>().Factory(), Cast.EO, Tag.Context(2), new Integer(20) ), 
			new ObjectInfo(new ObjectCreator<Integer				>().Factory(), Cast.EO, Tag.Context(3), trailerFieldBC  ), 
		}; 
		// конструктор при сериализации
        protected RSASSAPSSParams(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public RSASSAPSSParams(IEncodable encodable) : base(encodable, info) 
		{
			// проверить значение поля
			if (TrailerField.Value.IntValue > 0xFF) throw new InvalidDataException(); 
		}
		// конструктор при закодировании
		public RSASSAPSSParams(AlgorithmIdentifier hashAlgorithm, 
			AlgorithmIdentifier maskGenAlgorithm, Integer saltLength, Integer trailerField) : 
			base(info, hashAlgorithm, maskGenAlgorithm, saltLength, trailerField) 
		{
			// проверить значение поля
			if (TrailerField.Value.IntValue > 0xFF) throw new ArgumentException(); 
		}
		public AlgorithmIdentifier	HashAlgorithm		{ get { return (AlgorithmIdentifier	)this[0]; } } 
		public AlgorithmIdentifier	MaskGenAlgorithm	{ get { return (AlgorithmIdentifier	)this[1]; } }
		public Integer				SaltLength			{ get { return (Integer				)this[2]; } }
		public Integer				TrailerField		{ get { return (Integer				)this[3]; } }
	}
}
