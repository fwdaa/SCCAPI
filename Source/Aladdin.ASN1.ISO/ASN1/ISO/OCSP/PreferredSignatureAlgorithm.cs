using System;
using System.Runtime.Serialization;

// PreferredSignatureAlgorithm ::= SEQUENCE {
//    sigIdentifier  AlgorithmIdentifier{SIGNATURE-ALGORITHM, {...}},
//    certIdentifier AlgorithmIdentifier{PUBLIC-KEY, {...}} OPTIONAL
// }

namespace Aladdin.ASN1.ISO.OCSP
{
	[Serializable]
	public class PreferredSignatureAlgorithm : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<AlgorithmIdentifier>().Factory(), Cast.N), 
			new ObjectInfo(new ObjectCreator<AlgorithmIdentifier>().Factory(), Cast.O) 
		}; 
		// конструктор при сериализации
        protected PreferredSignatureAlgorithm(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public PreferredSignatureAlgorithm(IEncodable encodable) : base(encodable, info) {} 

		// конструктор при закодировании
		public PreferredSignatureAlgorithm(AlgorithmIdentifier sigIdentifier, AlgorithmIdentifier certIdentifier) : 
			base(info, sigIdentifier, certIdentifier) {} 

		public AlgorithmIdentifier	SigIdentifier	{ get { return (AlgorithmIdentifier	)this[0]; } } 
		public AlgorithmIdentifier	CertIdentifier	{ get { return (AlgorithmIdentifier	)this[1]; } }
	}
}
