using System;
using System.Runtime.Serialization;

//	RSAPrivateKey ::= SEQUENCE {
//		version			INTEGER,
//		modulus			INTEGER, 
//		publicExponent	INTEGER, 
//		privateExponent INTEGER, 
//		prime1			INTEGER, 
//		prime2			INTEGER, 
//		exponent1		INTEGER, 
//		exponent2		INTEGER, 
//		coefficient		INTEGER,
//		otherPrimeInfos OtherPrimeInfos OPTIONAL
//}

namespace Aladdin.ASN1.ISO.PKCS.PKCS1
{
	[Serializable]
	public class RSAPrivateKey : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<Integer			>().Factory(), Cast.N), 
			new ObjectInfo(new ObjectCreator<Integer			>().Factory(), Cast.N), 
			new ObjectInfo(new ObjectCreator<Integer			>().Factory(), Cast.N), 
			new ObjectInfo(new ObjectCreator<Integer			>().Factory(), Cast.N), 
			new ObjectInfo(new ObjectCreator<Integer			>().Factory(), Cast.N), 
			new ObjectInfo(new ObjectCreator<Integer			>().Factory(), Cast.N), 
			new ObjectInfo(new ObjectCreator<Integer			>().Factory(), Cast.N), 
			new ObjectInfo(new ObjectCreator<Integer			>().Factory(), Cast.N), 
			new ObjectInfo(new ObjectCreator<Integer			>().Factory(), Cast.N), 
			new ObjectInfo(new ObjectCreator<OtherPrimeInfos	>().Factory(), Cast.O), 
		}; 
		// конструктор при сериализации
        protected RSAPrivateKey(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public RSAPrivateKey(IEncodable encodable) : base(encodable, info) {}

		// конструктор при закодировании
		public RSAPrivateKey(Integer version, Integer modulus, Integer publicExponent, 
			Integer privateExponent, Integer prime1, Integer prime2, Integer exponent1, 
			Integer exponent2, Integer coefficient, OtherPrimeInfos otherPrimeInfos) : 
			base(info, version, modulus, publicExponent, privateExponent, prime1, prime2, 
			exponent1, exponent2, coefficient, otherPrimeInfos) {}

		public Integer			Version			{ get { return (Integer			)this[0]; } } 
		public Integer			Modulus			{ get { return (Integer			)this[1]; } } 
		public Integer			PublicExponent	{ get { return (Integer			)this[2]; } }
		public Integer			PrivateExponent	{ get { return (Integer			)this[3]; } } 
		public Integer			Prime1			{ get { return (Integer			)this[4]; } }
		public Integer			Prime2			{ get { return (Integer			)this[5]; } } 
		public Integer			Exponent1		{ get { return (Integer			)this[6]; } }
		public Integer			Exponent2		{ get { return (Integer			)this[7]; } } 
		public Integer			Coefficient		{ get { return (Integer			)this[8]; } }
		public OtherPrimeInfos	OtherPrimeInfos	{ get { return (OtherPrimeInfos	)this[9]; } }
	}
}
