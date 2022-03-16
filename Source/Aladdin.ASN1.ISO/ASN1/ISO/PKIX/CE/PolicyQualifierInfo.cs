using System; 
using System.Runtime.Serialization;

//	PolicyQualifierInfo ::= SEQUENCE {
//		policyQualifierId  OBJECT IDENTIFIER,
//		qualifier          ANY DEFINED BY policyQualifierId 
//	}

namespace Aladdin.ASN1.ISO.PKIX.CE
{
	[Serializable]
	public class PolicyQualifierInfo : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<ObjectIdentifier>().Factory(), Cast.N), 
			new ObjectInfo(    ImplicitCreator				    .Factory  , Cast.N), 
		}; 
		// конструктор при сериализации
        protected PolicyQualifierInfo(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public PolicyQualifierInfo(IEncodable encodable) : base(encodable, info) {}

		// конструктор при закодировании
		public PolicyQualifierInfo(ObjectIdentifier policyQualifierId, IEncodable qualifier) : 
			base(info, policyQualifierId, qualifier) {} 

		public ObjectIdentifier	PolicyQualifierId	{ get { return (ObjectIdentifier)this[0]; } } 
		public IEncodable	    Qualifier			{ get { return                   this[1]; } }
	}
}
