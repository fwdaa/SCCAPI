using System;
using System.IO;

//	RC2CBCParameter ::= SEQUENCE {
//		parameterVersion	INTEGER	OPTIONAL,
//		iv					OCTET STRING (SIZE(8))
//	}

namespace Aladdin.ASN1.ANSI.RSA
{
	public class RC2CBCParams : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<Integer	>().Factory(1, 1024), Cast.O), 
			new ObjectInfo(new ObjectCreator<OctetString>().Factory(8,    8), Cast.N), 
		}; 
		// конструктор при раскодировании
		public RC2CBCParams(IEncodable encodable) : base(encodable, info) {}

		// конструктор при закодировании
		public RC2CBCParams(Integer parameterVersion, OctetString iv) : 
			base(info, parameterVersion, iv) {}

		public Integer		ParameterVersion	{ get { return (Integer	   )this[0]; } }
		public OctetString	IV					{ get { return (OctetString)this[1]; } }
	}
}
