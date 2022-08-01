using System;
using System.Runtime.Serialization;

// CertID ::= SEQUENCE {
//     hashAlgorithm  AlgorithmIdentifier {DIGEST-ALGORITHM, {...}},
//     issuerNameHash OCTET STRING, 
//     issuerKeyHash  OCTET STRING, 
//     serialNumber   INTEGER
// }

namespace Aladdin.ASN1.ISO.OCSP
{
	[Serializable]
	public class CertID : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<AlgorithmIdentifier>().Factory(), Cast.N), 
			new ObjectInfo(new ObjectCreator<OctetString        >().Factory(), Cast.N), 
			new ObjectInfo(new ObjectCreator<OctetString        >().Factory(), Cast.N),  
			new ObjectInfo(new ObjectCreator<Integer            >().Factory(), Cast.N)  
		}; 
		// конструктор при сериализации
        protected CertID(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public CertID(IEncodable encodable) : base(encodable, info) {} 

		// конструктор при закодировании
		public CertID(AlgorithmIdentifier hashAlgorithm, OctetString issuerNameHash, 
			OctetString issuerKeyHash, Integer serialNumber) : 
			base(info, hashAlgorithm, issuerNameHash, issuerKeyHash, serialNumber) {} 

		public AlgorithmIdentifier		HashAlgorithm	{ get { return (AlgorithmIdentifier )this[0]; } } 
		public OctetString 				IssuerNameHash	{ get { return (OctetString         )this[1]; } }
		public OctetString				IssuerKeyHash	{ get { return (OctetString			)this[2]; } }
		public Integer					SerialNumber	{ get { return (Integer				)this[3]; } }
	}
}
