using System;
using System.Collections.Generic;
using System.Runtime.Serialization; 

//	GOSTR3411ParamSet ::= SEQUENCE {
//		hUZ OCTET STRING (SIZE(64)),    
//		h0  OCTET STRING (SIZE(32))
//	}

namespace Aladdin.ASN1.GOST
{
    [Serializable]
	public class GOSTR3411ParamSet1994 : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<OctetString>().Factory(64, 64), Cast.N), 
			new ObjectInfo(new ObjectCreator<OctetString>().Factory(32, 32), Cast.N), 
		}; 
		// конструктор при сериализации
        protected GOSTR3411ParamSet1994(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public GOSTR3411ParamSet1994(IEncodable encodable) : base(encodable, info) {}

		// конструктор при закодировании
		public GOSTR3411ParamSet1994(OctetString hUZ, OctetString h0) : base(info, hUZ, h0) {}

		public OctetString HUZ	{ get { return (OctetString)this[0]; } } 
		public OctetString H0	{ get { return (OctetString)this[1]; } }

		// таблица именованных параметров
		private static readonly Dictionary<String, GOSTR3411ParamSet1994> set = 
			new Dictionary<String, GOSTR3411ParamSet1994>(); 

	    // стартовое значение
	    private static readonly byte[] H0_TEST = new byte[] {
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
		}; 
	    private static readonly byte[] H0_CRYPTOPRO = new byte[] {
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
		}; 
		static GOSTR3411ParamSet1994()
		{
			set.Add(OID.hashes_test, new GOSTR3411ParamSet1994(
    			GOST28147SBoxReference.Parameters(OID.hashes_test), new OctetString(H0_TEST)
			)); 
			set.Add(OID.hashes_cryptopro, new GOSTR3411ParamSet1994(
    			GOST28147SBoxReference.Parameters(OID.hashes_cryptopro), new OctetString(H0_CRYPTOPRO)
			)); 
		}
		// получить именованные параметры
		public static GOSTR3411ParamSet1994 Parameters(string oid) { return set[oid]; } 
    }
}
