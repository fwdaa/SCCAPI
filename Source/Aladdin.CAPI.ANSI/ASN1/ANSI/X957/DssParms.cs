using System;
using System.Collections.Generic;

// DssParms ::= SEQUENCE {
//		p            INTEGER,
//		q            INTEGER,
//		g            INTEGER
// }

namespace Aladdin.ASN1.ANSI.X957
{
	public class DssParms : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<Integer>().Factory(), Cast.N), 
			new ObjectInfo(new ObjectCreator<Integer>().Factory(), Cast.N), 
			new ObjectInfo(new ObjectCreator<Integer>().Factory(), Cast.N), 
		}; 
		// конструктор при раскодировании
		public DssParms(IEncodable encodable) : base(encodable, info) {}

		// конструктор при закодировании
		public DssParms(Integer p, Integer q, Integer g) : 
			base(info, p, q, g) {}

		public Integer P { get { return (Integer)this[0]; } }
		public Integer Q { get { return (Integer)this[1]; } }
		public Integer G { get { return (Integer)this[2]; } }

        // идентификатор набора параметры ключей 
        public OctetString GetDomainID() 
        { 
            // выделить память для идентификатора
            byte[] id = new byte[10]; byte[] encoded = Encoded;
        
            // получить алгоритм хэширования
            using (CAPI.Hash hashAlgorithm = new CAPI.ANSI.Hash.SHA1())
            { 
                // выполнить хэширование
                byte[] hash = hashAlgorithm.HashData(encoded, 0, encoded.Length); 
        
                // вычислить идентификатор
                for (int i = 0; i < id.Length; i++) id[i] = (byte)(hash[i] ^ hash[10 + i]); 
            }        
            // вернуть идентификатор
            return new OctetString(id); 
        }
        ////////////////////////////////////////////////////////////////////////////
	    // именованные параметры
        ////////////////////////////////////////////////////////////////////////////
	    private static readonly Math.BigInteger Ephemeral_P = 
            new Math.BigInteger(1, new byte[] {
		    (byte)0x87, (byte)0x10, (byte)0xfa, (byte)0x72, 
            (byte)0x11, (byte)0xb8, (byte)0x1f, (byte)0x26, 
		    (byte)0x78, (byte)0x8c, (byte)0xfa, (byte)0xcb, 
            (byte)0x99, (byte)0x01, (byte)0xa0, (byte)0xbd,
		    (byte)0x39, (byte)0xc8, (byte)0x54, (byte)0xef, 
            (byte)0x35, (byte)0x68, (byte)0x3a, (byte)0x2a, 
		    (byte)0xb7, (byte)0x0c, (byte)0x0a, (byte)0xc9, 
            (byte)0xed, (byte)0x62, (byte)0x5c, (byte)0x16,
		    (byte)0x97, (byte)0xe4, (byte)0x56, (byte)0x8c, 
            (byte)0x69, (byte)0xeb, (byte)0xce, (byte)0xda, 
		    (byte)0x46, (byte)0x8a, (byte)0xcc, (byte)0x9e, 
            (byte)0x77, (byte)0x7f, (byte)0x47, (byte)0x46,
		    (byte)0x6d, (byte)0x5a, (byte)0xcb, (byte)0xc6, 
            (byte)0x87, (byte)0xcc, (byte)0x0f, (byte)0x0d, 
		    (byte)0xea, (byte)0x7f, (byte)0xe9, (byte)0x4d, 
            (byte)0x80, (byte)0x94, (byte)0x76, (byte)0xe7,
		    (byte)0x33, (byte)0x10, (byte)0xd5, (byte)0xb0, 
            (byte)0xb5, (byte)0x28, (byte)0x06, (byte)0xcf, 
		    (byte)0x96, (byte)0x9d, (byte)0x48, (byte)0x64, 
            (byte)0x7b, (byte)0x7d, (byte)0x5e, (byte)0x41,
		    (byte)0x49, (byte)0x20, (byte)0x2d, (byte)0xfe, 
            (byte)0x79, (byte)0x14, (byte)0xce, (byte)0x62, 
		    (byte)0x5a, (byte)0xfd, (byte)0x77, (byte)0x20, 
            (byte)0x19, (byte)0xbb, (byte)0xaf, (byte)0xef,
		    (byte)0xba, (byte)0x81, (byte)0x03, (byte)0x6c, 
            (byte)0xb0, (byte)0xa1, (byte)0x05, (byte)0x98, 
		    (byte)0xdc, (byte)0x7b, (byte)0xc0, (byte)0xef, 
            (byte)0x6f, (byte)0x4d, (byte)0x9a, (byte)0xf8,
		    (byte)0x62, (byte)0x7e, (byte)0x06, (byte)0xc1, 
            (byte)0x76, (byte)0x1d, (byte)0x3b, (byte)0x38, 
		    (byte)0xe9, (byte)0x5c, (byte)0x86, (byte)0x0e, 
            (byte)0x96, (byte)0x90, (byte)0x2a, (byte)0x6d,
	    });
	    private static readonly Math.BigInteger Ephemeral_G = 
            new Math.BigInteger(1, new byte[] {
		    (byte)0x20, (byte)0x82, (byte)0xf3, (byte)0x07, 
            (byte)0xae, (byte)0x29, (byte)0x67, (byte)0x63, 
		    (byte)0x40, (byte)0x78, (byte)0x5d, (byte)0xc5, 
            (byte)0xfd, (byte)0x4e, (byte)0xa2, (byte)0x0d,
		    (byte)0x14, (byte)0x79, (byte)0x6b, (byte)0x8c, 
            (byte)0x13, (byte)0x55, (byte)0xb2, (byte)0x0f, 
		    (byte)0x9c, (byte)0x27, (byte)0x79, (byte)0x74, 
            (byte)0xf5, (byte)0x90, (byte)0x10, (byte)0xa4,
		    (byte)0xe6, (byte)0xb5, (byte)0x97, (byte)0x59, 
            (byte)0x9e, (byte)0x58, (byte)0x0f, (byte)0xf1, 
		    (byte)0x27, (byte)0xcc, (byte)0xcc, (byte)0x05, 
            (byte)0xbd, (byte)0x93, (byte)0xa8, (byte)0x87,
		    (byte)0xe0, (byte)0x18, (byte)0xdc, (byte)0x14, 
            (byte)0x94, (byte)0x5e, (byte)0x58, (byte)0x2a, 
		    (byte)0xae, (byte)0xa0, (byte)0x11, (byte)0x56, 
            (byte)0x44, (byte)0x4e, (byte)0x15, (byte)0x17,
		    (byte)0x18, (byte)0x35, (byte)0xdb, (byte)0xaa, 
            (byte)0x65, (byte)0x34, (byte)0x0f, (byte)0x44, 
		    (byte)0x54, (byte)0xf8, (byte)0x40, (byte)0x7e, 
            (byte)0x2c, (byte)0x12, (byte)0xe2, (byte)0x10,
		    (byte)0xb7, (byte)0x7f, (byte)0x23, (byte)0xe6, 
            (byte)0x11, (byte)0x36, (byte)0x4d, (byte)0x7b, 
		    (byte)0x99, (byte)0xdb, (byte)0x0d, (byte)0x73, 
            (byte)0x0a, (byte)0x86, (byte)0x5d, (byte)0xb3,
		    (byte)0x56, (byte)0x85, (byte)0x98, (byte)0x2b, 
            (byte)0xf7, (byte)0xb5, (byte)0x30, (byte)0x92, 
		    (byte)0xfd, (byte)0x30, (byte)0x89, (byte)0xe8, 
            (byte)0xd3, (byte)0xb0, (byte)0x49, (byte)0x3d,
		    (byte)0x03, (byte)0x47, (byte)0x1c, (byte)0x14, 
            (byte)0x00, (byte)0x7d, (byte)0x1f, (byte)0x6d, 
		    (byte)0x07, (byte)0xca, (byte)0x79, (byte)0x12, 
            (byte)0xc9, (byte)0x34, (byte)0xf3, (byte)0xc4,
	    });
	    private static readonly Math.BigInteger Ephemeral_Q = 
            new Math.BigInteger(1, new byte[] {
		    (byte)0x85, (byte)0x77, (byte)0xf6, (byte)0xe5, 
            (byte)0xbc, (byte)0xeb, (byte)0x2d, (byte)0x3e,
		    (byte)0x90, (byte)0x21, (byte)0x39, (byte)0x47, 
            (byte)0x20, (byte)0xce, (byte)0xae, (byte)0x7c,
		    (byte)0x14, (byte)0x3d, (byte)0xe5, (byte)0xa1,
	    });
	    // экземпляр параметров
	    public static readonly DssParms Ephemeral = new DssParms(
		    new Integer(Ephemeral_P), new Integer(Ephemeral_Q), new Integer(Ephemeral_G) 
	    ); 
	    // таблица именованных параметров
	    private static readonly Dictionary<OctetString, DssParms> set = 
		    new Dictionary<OctetString, DssParms>(); 
	    static DssParms() 
        {
            // добавить именованные параметры в список
            set.Add(Ephemeral.GetDomainID(), Ephemeral); 
	    }
	    // получить именованные параметры
	    public static DssParms Parameters(OctetString oid) { return set[oid]; } 
    }
}
