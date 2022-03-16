using System;
using System.Collections.Generic;
using System.Runtime.Serialization; 

//	GOST28147ParamSet ::= SEQUENCE {
//		eUZ             OCTET STRING (SIZE(64)),
//		mode            Mode,
//		shiftBits       INTEGER { block(64) },
//		keyMeshing      AlgorithmIdentifier
//	}

namespace Aladdin.ASN1.GOST
{
    [Serializable]
	public class GOST28147ParamSet : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<OctetString			>().Factory(64, 64), Cast.N), 
			new ObjectInfo(new ObjectCreator<Integer				>().Factory(      ), Cast.N), 
			new ObjectInfo(new ObjectCreator<Integer				>().Factory(64, 64), Cast.N), 
			new ObjectInfo(new ObjectCreator<ISO.AlgorithmIdentifier>().Factory(      ), Cast.N), 
		}; 
		// конструктор при сериализации
        protected GOST28147ParamSet(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public GOST28147ParamSet(IEncodable encodable) : base(encodable, info) {}

		// конструктор при закодировании
		public GOST28147ParamSet(OctetString eUZ, Integer mode, Integer shiftBits, 
            ISO.AlgorithmIdentifier keyMeshing) : base(info, eUZ, mode, shiftBits, keyMeshing) {}

		public OctetString				EUZ			{ get { return (OctetString				)this[0]; } } 
		public Integer					Mode		{ get { return (Integer					)this[1]; } }
		public Integer					ShiftBits	{ get { return (Integer					)this[2]; } }
		public ISO.AlgorithmIdentifier	KeyMeshing	{ get { return (ISO.AlgorithmIdentifier	)this[3]; } }

		// таблица именованных параметров
		private static readonly Dictionary<String, GOST28147ParamSet> set = 
			new Dictionary<String, GOST28147ParamSet>(); 

		static GOST28147ParamSet()
		{
			set.Add(OID.encrypts_test, new GOST28147ParamSet(
			    GOST28147SBoxReference.Parameters(OID.encrypts_test), 
                new Integer(GOST28147CipherMode.CTR), 
                new Integer(64), new ISO.AlgorithmIdentifier(
				    new ASN1.ObjectIdentifier(OID.keyMeshing_none), 
                    Null.Instance
		    ))); 
			set.Add(OID.encrypts_A, new GOST28147ParamSet(
			    GOST28147SBoxReference.Parameters(OID.encrypts_A), 
                new Integer(GOST28147CipherMode.CFB), 
                new Integer(64), new ISO.AlgorithmIdentifier(
				    new ASN1.ObjectIdentifier(OID.keyMeshing_cryptopro), 
                    Null.Instance
		    ))); 
			set.Add(OID.encrypts_B, new GOST28147ParamSet(
			    GOST28147SBoxReference.Parameters(OID.encrypts_B), 
                new Integer(GOST28147CipherMode.CFB), 
                new Integer(64), new ISO.AlgorithmIdentifier(
				    new ASN1.ObjectIdentifier(OID.keyMeshing_cryptopro), 
                    Null.Instance
		    ))); 
			set.Add(OID.encrypts_C, new GOST28147ParamSet(
			    GOST28147SBoxReference.Parameters(OID.encrypts_C), 
                new Integer(GOST28147CipherMode.CFB), 
                new Integer(64), new ISO.AlgorithmIdentifier(
				    new ASN1.ObjectIdentifier(OID.keyMeshing_cryptopro), 
                    Null.Instance
		    ))); 
			set.Add(OID.encrypts_D, new GOST28147ParamSet(
			    GOST28147SBoxReference.Parameters(OID.encrypts_D), 
                new Integer(GOST28147CipherMode.CFB), 
                new Integer(64), new ISO.AlgorithmIdentifier(
				    new ASN1.ObjectIdentifier(OID.keyMeshing_cryptopro), 
                    Null.Instance
		    ))); 
			set.Add(OID.encrypts_tc26_z, new GOST28147ParamSet(
			    GOST28147SBoxReference.Parameters(OID.encrypts_tc26_z), 
                new Integer(GOST28147CipherMode.CFB), 
                new Integer(64), new ISO.AlgorithmIdentifier(
				    new ASN1.ObjectIdentifier(OID.keyMeshing_cryptopro), 
                    Null.Instance
		    ))); 
		}
		// получить именованные параметры
		public static GOST28147ParamSet Parameters(string oid) { return set[oid]; } 
    }
}
