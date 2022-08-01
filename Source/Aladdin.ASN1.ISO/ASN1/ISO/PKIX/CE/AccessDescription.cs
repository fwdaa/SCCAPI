using System;
using System.Runtime.Serialization;

// AccessDescription  ::=  SEQUENCE {
//		accessMethod   OBJECT IDENTIFIER,
//      accessLocation GeneralName  
// }

namespace Aladdin.ASN1.ISO.PKIX.CE
{
	[Serializable]
	public class AccessDescription : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<ObjectIdentifier>().Factory(), Cast.N), 
			new ObjectInfo(new ChoiceCreator<GeneralName	 >().Factory(), Cast.N) 
		}; 
		// конструктор при сериализации
        protected AccessDescription(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public AccessDescription(IEncodable encodable) : base(encodable, info) {}

		// конструктор при закодировании
		public AccessDescription(ObjectIdentifier accessMethod, IEncodable accessLocation) : 
			base(info, accessMethod, accessLocation) {}

		public ObjectIdentifier	AccessMethod	{ get { return (ObjectIdentifier)this[0]; }} 
		public IEncodable		AccessLocation	{ get { return (IEncodable		)this[1]; }}
	}
}
