using System;
using System.Collections.Generic;
using System.Runtime.Serialization; 

//	GOSTR3410ParamSet ::= SEQUENCE {
//		a INTEGER,
//		b INTEGER,
//		p INTEGER,
//		q INTEGER,
//		x INTEGER,
//		y INTEGER
//	}

namespace Aladdin.ASN1.GOST
{
    [Serializable]
	public class GOSTR3410ParamSet : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<Integer>().Factory(), Cast.N), 
			new ObjectInfo(new ObjectCreator<Integer>().Factory(), Cast.N), 
			new ObjectInfo(new ObjectCreator<Integer>().Factory(), Cast.N), 
			new ObjectInfo(new ObjectCreator<Integer>().Factory(), Cast.N), 
			new ObjectInfo(new ObjectCreator<Integer>().Factory(), Cast.N), 
			new ObjectInfo(new ObjectCreator<Integer>().Factory(), Cast.N), 
		}; 
		// конструктор при сериализации
        protected GOSTR3410ParamSet(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public GOSTR3410ParamSet(IEncodable encodable) : base(encodable, info) {}
		
		// конструктор при закодировании
		public GOSTR3410ParamSet(Integer a, Integer b, Integer p, Integer q, Integer x, Integer y) : 
			base(info, a, b, p, q, x, y) {}  

		public Integer A { get { return (Integer)this[0]; } } 
		public Integer B { get { return (Integer)this[1]; } } 
		public Integer P { get { return (Integer)this[2]; } } 
		public Integer Q { get { return (Integer)this[3]; } } 
		public Integer X { get { return (Integer)this[4]; } } 
		public Integer Y { get { return (Integer)this[5]; } } 

        ////////////////////////////////////////////////////////////////////////////
	    // Наборы параметров
        ////////////////////////////////////////////////////////////////////////////
	    public static readonly Math.BigInteger Sign256T_A = new Math.BigInteger(1, new byte[] { (byte)0x07 });
	    public static readonly Math.BigInteger Sign256T_B = new Math.BigInteger(1, new byte[] {
		    (byte)0x5F, (byte)0xBF, (byte)0xF4, (byte)0x98, 
            (byte)0xAA, (byte)0x93, (byte)0x8C, (byte)0xE7, 
		    (byte)0x39, (byte)0xB8, (byte)0xE0, (byte)0x22, 
            (byte)0xFB, (byte)0xAF, (byte)0xEF, (byte)0x40,
		    (byte)0x56, (byte)0x3F, (byte)0x6E, (byte)0x6A, 
            (byte)0x34, (byte)0x72, (byte)0xFC, (byte)0x2A, 
		    (byte)0x51, (byte)0x4C, (byte)0x0C, (byte)0xE9, 
            (byte)0xDA, (byte)0xE2, (byte)0x3B, (byte)0x7E,
	    });
	    public static readonly Math.BigInteger Sign256T_P = new Math.BigInteger(1, new byte[] { 
		    (byte)0x80, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
		    (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
		    (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
		    (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x04, (byte)0x31,
	    });
	    public static readonly Math.BigInteger Sign256T_Q = new Math.BigInteger(1, new byte[] { 
		    (byte)0x80, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
		    (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x01, 
		    (byte)0x50, (byte)0xFE, (byte)0x8A, (byte)0x18, 
            (byte)0x92, (byte)0x97, (byte)0x61, (byte)0x54, 
		    (byte)0xC5, (byte)0x9C, (byte)0xFC, (byte)0x19, 
            (byte)0x3A, (byte)0xCC, (byte)0xF5, (byte)0xB3,
	    });
	    public static readonly Math.BigInteger Sign256T_X = new Math.BigInteger(1, new byte[] { (byte)0x02 });
	    public static readonly Math.BigInteger Sign256T_Y = new Math.BigInteger(1, new byte[] {
		    (byte)0x08, (byte)0xE2, (byte)0xA8, (byte)0xA0, 
            (byte)0xE6, (byte)0x51, (byte)0x47, (byte)0xD4, 
		    (byte)0xBD, (byte)0x63, (byte)0x16, (byte)0x03, 
            (byte)0x0E, (byte)0x16, (byte)0xD1, (byte)0x9C,
		    (byte)0x85, (byte)0xC9, (byte)0x7F, (byte)0x0A, 
            (byte)0x9C, (byte)0xA2, (byte)0x67, (byte)0x12, 
		    (byte)0x2B, (byte)0x96, (byte)0xAB, (byte)0xBC, 
            (byte)0xEA, (byte)0x7E, (byte)0x8F, (byte)0xC8,
	    }); 
	    // параметры алгоритма
	    public static readonly Math.BigInteger Sign256A_A = new Math.BigInteger(1, new byte[] { 
		    (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
		    (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
		    (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
		    (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFD, (byte)0x94,
	    });
	    public static readonly Math.BigInteger Sign256A_B = new Math.BigInteger(1, new byte[] { (byte)0xA6 });
	    public static readonly Math.BigInteger Sign256A_P = new Math.BigInteger(1, new byte[] { 
		    (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
		    (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
		    (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
		    (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFD, (byte)0x97,
	    });
	    public static readonly Math.BigInteger Sign256A_Q = new Math.BigInteger(1, new byte[] { 
		    (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
		    (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
		    (byte)0x6C, (byte)0x61, (byte)0x10, (byte)0x70, 
            (byte)0x99, (byte)0x5A, (byte)0xD1, (byte)0x00, 
		    (byte)0x45, (byte)0x84, (byte)0x1B, (byte)0x09, 
            (byte)0xB7, (byte)0x61, (byte)0xB8, (byte)0x93, 
	    });
	    public static readonly Math.BigInteger Sign256A_X = new Math.BigInteger(1, new byte[] { (byte)0x01 });
	    public static readonly Math.BigInteger Sign256A_Y = new Math.BigInteger(1, new byte[] { 
		    (byte)0x8D, (byte)0x91, (byte)0xE4, (byte)0x71, 
            (byte)0xE0, (byte)0x98, (byte)0x9C, (byte)0xDA, 
		    (byte)0x27, (byte)0xDF, (byte)0x50, (byte)0x5A, 
            (byte)0x45, (byte)0x3F, (byte)0x2B, (byte)0x76, 
		    (byte)0x35, (byte)0x29, (byte)0x4F, (byte)0x2D, 
            (byte)0xDF, (byte)0x23, (byte)0xE3, (byte)0xB1, 
		    (byte)0x22, (byte)0xAC, (byte)0xC9, (byte)0x9C, 
            (byte)0x9E, (byte)0x9F, (byte)0x1E, (byte)0x14, 
	    }); 
	    // параметры алгоритма
	    public static readonly Math.BigInteger Sign256B_A = new Math.BigInteger(1, new byte[] { 
		    (byte)0x80, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
		    (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
		    (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
		    (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x0C, (byte)0x96,
	    });
	    public static readonly Math.BigInteger Sign256B_B = new Math.BigInteger(1, new byte[] {
		    (byte)0x3E, (byte)0x1A, (byte)0xF4, (byte)0x19, 
            (byte)0xA2, (byte)0x69, (byte)0xA5, (byte)0xF8, 
		    (byte)0x66, (byte)0xA7, (byte)0xD3, (byte)0xC2, 
            (byte)0x5C, (byte)0x3D, (byte)0xF8, (byte)0x0A,
		    (byte)0xE9, (byte)0x79, (byte)0x25, (byte)0x93, 
            (byte)0x73, (byte)0xFF, (byte)0x2B, (byte)0x18, 
		    (byte)0x2F, (byte)0x49, (byte)0xD4, (byte)0xCE, 
            (byte)0x7E, (byte)0x1B, (byte)0xBC, (byte)0x8B,
	    });
	    public static readonly Math.BigInteger Sign256B_P = new Math.BigInteger(1, new byte[] { 
		    (byte)0x80, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
		    (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
		    (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
		    (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x0C, (byte)0x99,
	    });
	    public static readonly Math.BigInteger Sign256B_Q = new Math.BigInteger(1, new byte[] { 
		    (byte)0x80, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
		    (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x01, 
		    (byte)0x5F, (byte)0x70, (byte)0x0C, (byte)0xFF, 
            (byte)0xF1, (byte)0xA6, (byte)0x24, (byte)0xE5, 
		    (byte)0xE4, (byte)0x97, (byte)0x16, (byte)0x1B, 
            (byte)0xCC, (byte)0x8A, (byte)0x19, (byte)0x8F,
	    });
	    public static readonly Math.BigInteger Sign256B_X = new Math.BigInteger(1, new byte[] { (byte)0x01 });
	    public static readonly Math.BigInteger Sign256B_Y = new Math.BigInteger(1, new byte[] { 
		    (byte)0x3F, (byte)0xA8, (byte)0x12, (byte)0x43, 
            (byte)0x59, (byte)0xF9, (byte)0x66, (byte)0x80, 
		    (byte)0xB8, (byte)0x3D, (byte)0x1C, (byte)0x3E, 
            (byte)0xB2, (byte)0xC0, (byte)0x70, (byte)0xE5,
		    (byte)0xC5, (byte)0x45, (byte)0xC9, (byte)0x85, 
            (byte)0x8D, (byte)0x03, (byte)0xEC, (byte)0xFB, 
		    (byte)0x74, (byte)0x4B, (byte)0xF8, (byte)0xD7, 
            (byte)0x17, (byte)0x71, (byte)0x7E, (byte)0xFC,
	    }); 
	    // параметры алгоритма
	    public static readonly Math.BigInteger Sign256C_A = new Math.BigInteger(1, new byte[] { 
		    (byte)0x9B, (byte)0x9F, (byte)0x60, (byte)0x5F, 
            (byte)0x5A, (byte)0x85, (byte)0x81, (byte)0x07, 
		    (byte)0xAB, (byte)0x1E, (byte)0xC8, (byte)0x5E, 
            (byte)0x6B, (byte)0x41, (byte)0xC8, (byte)0xAA, 
		    (byte)0xCF, (byte)0x84, (byte)0x6E, (byte)0x86, 
            (byte)0x78, (byte)0x90, (byte)0x51, (byte)0xD3, 
		    (byte)0x79, (byte)0x98, (byte)0xF7, (byte)0xB9, 
            (byte)0x02, (byte)0x2D, (byte)0x75, (byte)0x98,
	    });
	    public static readonly Math.BigInteger Sign256C_B = new Math.BigInteger(1, new byte[] { (byte)0x80, (byte)0x5A });
	    public static readonly Math.BigInteger Sign256C_P = new Math.BigInteger(1, new byte[] {  
		    (byte)0x9B, (byte)0x9F, (byte)0x60, (byte)0x5F, 
            (byte)0x5A, (byte)0x85, (byte)0x81, (byte)0x07, 
		    (byte)0xAB, (byte)0x1E, (byte)0xC8, (byte)0x5E, 
            (byte)0x6B, (byte)0x41, (byte)0xC8, (byte)0xAA, 
		    (byte)0xCF, (byte)0x84, (byte)0x6E, (byte)0x86, 
            (byte)0x78, (byte)0x90, (byte)0x51, (byte)0xD3, 
		    (byte)0x79, (byte)0x98, (byte)0xF7, (byte)0xB9, 
            (byte)0x02, (byte)0x2D, (byte)0x75, (byte)0x9B,
	    });
	    public static readonly Math.BigInteger Sign256C_Q = new Math.BigInteger(1, new byte[] { 
		    (byte)0x9B, (byte)0x9F, (byte)0x60, (byte)0x5F, 
            (byte)0x5A, (byte)0x85, (byte)0x81, (byte)0x07, 
		    (byte)0xAB, (byte)0x1E, (byte)0xC8, (byte)0x5E, 
            (byte)0x6B, (byte)0x41, (byte)0xC8, (byte)0xAA, 
		    (byte)0x58, (byte)0x2C, (byte)0xA3, (byte)0x51, 
            (byte)0x1E, (byte)0xDD, (byte)0xFB, (byte)0x74, 
		    (byte)0xF0, (byte)0x2F, (byte)0x3A, (byte)0x65, 
            (byte)0x98, (byte)0x98, (byte)0x0B, (byte)0xB9,
	    });
	    public static readonly Math.BigInteger Sign256C_X = new Math.BigInteger(1, new byte[] { (byte)0x00 });
	    public static readonly Math.BigInteger Sign256C_Y = new Math.BigInteger(1, new byte[] { 
		    (byte)0x41, (byte)0xEC, (byte)0xE5, (byte)0x57, 
            (byte)0x43, (byte)0x71, (byte)0x1A, (byte)0x8C, 
		    (byte)0x3C, (byte)0xBF, (byte)0x37, (byte)0x83, 
            (byte)0xCD, (byte)0x08, (byte)0xC0, (byte)0xEE,
		    (byte)0x4D, (byte)0x4D, (byte)0xC4, (byte)0x40, 
            (byte)0xD4, (byte)0x64, (byte)0x1A, (byte)0x8F, 
		    (byte)0x36, (byte)0x6E, (byte)0x55, (byte)0x0D, 
            (byte)0xFD, (byte)0xB3, (byte)0xBB, (byte)0x67,
	    }); 
	    public static readonly Math.BigInteger Keyx256A_A = new Math.BigInteger(1, new byte[] { 
		    (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
		    (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
		    (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
		    (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFD, (byte)0x94,
	    });
	    public static readonly Math.BigInteger Keyx256A_B = new Math.BigInteger(1, new byte[] { (byte)0xA6 });
	    public static readonly Math.BigInteger Keyx256A_P = new Math.BigInteger(1, new byte[] {  
		    (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
		    (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
		    (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
		    (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFD, (byte)0x97,
	    });
	    public static readonly Math.BigInteger Keyx256A_Q = new Math.BigInteger(1, new byte[] { 
		    (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
		    (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
		    (byte)0x6C, (byte)0x61, (byte)0x10, (byte)0x70, 
            (byte)0x99, (byte)0x5A, (byte)0xD1, (byte)0x00, 
		    (byte)0x45, (byte)0x84, (byte)0x1B, (byte)0x09, 
            (byte)0xB7, (byte)0x61, (byte)0xB8, (byte)0x93, 
	    });
	    public static readonly Math.BigInteger Keyx256A_X = new Math.BigInteger(1, new byte[] { (byte)0x01 });
	    public static readonly Math.BigInteger Keyx256A_Y = new Math.BigInteger(1, new byte[] { 
		    (byte)0x8D, (byte)0x91, (byte)0xE4, (byte)0x71, 
            (byte)0xE0, (byte)0x98, (byte)0x9C, (byte)0xDA, 
		    (byte)0x27, (byte)0xDF, (byte)0x50, (byte)0x5A, 
            (byte)0x45, (byte)0x3F, (byte)0x2B, (byte)0x76, 
		    (byte)0x35, (byte)0x29, (byte)0x4F, (byte)0x2D, 
            (byte)0xDF, (byte)0x23, (byte)0xE3, (byte)0xB1, 
		    (byte)0x22, (byte)0xAC, (byte)0xC9, (byte)0x9C, 
            (byte)0x9E, (byte)0x9F, (byte)0x1E, (byte)0x14, 
	    }); 
	    public static readonly Math.BigInteger Keyx256B_A = new Math.BigInteger(1, new byte[] { 
		    (byte)0x9B, (byte)0x9F, (byte)0x60, (byte)0x5F, 
            (byte)0x5A, (byte)0x85, (byte)0x81, (byte)0x07, 
		    (byte)0xAB, (byte)0x1E, (byte)0xC8, (byte)0x5E, 
            (byte)0x6B, (byte)0x41, (byte)0xC8, (byte)0xAA, 
		    (byte)0xCF, (byte)0x84, (byte)0x6E, (byte)0x86, 
            (byte)0x78, (byte)0x90, (byte)0x51, (byte)0xD3, 
		    (byte)0x79, (byte)0x98, (byte)0xF7, (byte)0xB9, 
            (byte)0x02, (byte)0x2D, (byte)0x75, (byte)0x98,
	    });
	    public static readonly Math.BigInteger Keyx256B_B = new Math.BigInteger(1, new byte[] { (byte)0x80, (byte)0x5A });
	    public static readonly Math.BigInteger Keyx256B_P = new Math.BigInteger(1, new byte[] { 
		    (byte)0x9B, (byte)0x9F, (byte)0x60, (byte)0x5F, 
            (byte)0x5A, (byte)0x85, (byte)0x81, (byte)0x07, 
		    (byte)0xAB, (byte)0x1E, (byte)0xC8, (byte)0x5E, 
            (byte)0x6B, (byte)0x41, (byte)0xC8, (byte)0xAA, 
		    (byte)0xCF, (byte)0x84, (byte)0x6E, (byte)0x86, 
            (byte)0x78, (byte)0x90, (byte)0x51, (byte)0xD3, 
		    (byte)0x79, (byte)0x98, (byte)0xF7, (byte)0xB9, 
            (byte)0x02, (byte)0x2D, (byte)0x75, (byte)0x9B,
	    });
	    public static readonly Math.BigInteger Keyx256B_Q = new Math.BigInteger(1, new byte[] { 
		    (byte)0x9B, (byte)0x9F, (byte)0x60, (byte)0x5F, 
            (byte)0x5A, (byte)0x85, (byte)0x81, (byte)0x07, 
		    (byte)0xAB, (byte)0x1E, (byte)0xC8, (byte)0x5E, 
            (byte)0x6B, (byte)0x41, (byte)0xC8, (byte)0xAA, 
		    (byte)0x58, (byte)0x2C, (byte)0xA3, (byte)0x51, 
            (byte)0x1E, (byte)0xDD, (byte)0xFB, (byte)0x74, 
		    (byte)0xF0, (byte)0x2F, (byte)0x3A, (byte)0x65, 
            (byte)0x98, (byte)0x98, (byte)0x0B, (byte)0xB9,
	    });
	    public static readonly Math.BigInteger Keyx256B_X = new Math.BigInteger(1, new byte[] { (byte)0x00 });
	    public static readonly Math.BigInteger Keyx256B_Y = new Math.BigInteger(1, new byte[] { 
		    (byte)0x41, (byte)0xEC, (byte)0xE5, (byte)0x57, 
            (byte)0x43, (byte)0x71, (byte)0x1A, (byte)0x8C, 
		    (byte)0x3C, (byte)0xBF, (byte)0x37, (byte)0x83, 
            (byte)0xCD, (byte)0x08, (byte)0xC0, (byte)0xEE,
		    (byte)0x4D, (byte)0x4D, (byte)0xC4, (byte)0x40, 
            (byte)0xD4, (byte)0x64, (byte)0x1A, (byte)0x8F, 
		    (byte)0x36, (byte)0x6E, (byte)0x55, (byte)0x0D, 
            (byte)0xFD, (byte)0xB3, (byte)0xBB, (byte)0x67,
	    }); 
        // параметры алгоритма
	    public static readonly Math.BigInteger SignX256A_A = new Math.BigInteger(1, new byte[] { 
            (byte)0xC2, (byte)0x17, (byte)0x3F, (byte)0x15, 
            (byte)0x13, (byte)0x98, (byte)0x16, (byte)0x73, 
            (byte)0xAF, (byte)0x48, (byte)0x92, (byte)0xC2, 
            (byte)0x30, (byte)0x35, (byte)0xA2, (byte)0x7C, 
            (byte)0xE2, (byte)0x5E, (byte)0x20, (byte)0x13, 
            (byte)0xBF, (byte)0x95, (byte)0xAA, (byte)0x33, 
            (byte)0xB2, (byte)0x2C, (byte)0x65, (byte)0x6F, 
            (byte)0x27, (byte)0x7E, (byte)0x73, (byte)0x35
        });
	    public static readonly Math.BigInteger SignX256A_B = new Math.BigInteger(1, new byte[] { 
            (byte)0x29, (byte)0x5F, (byte)0x9B, (byte)0xAE, 
            (byte)0x74, (byte)0x28, (byte)0xED, (byte)0x9C, 
            (byte)0xCC, (byte)0x20, (byte)0xE7, (byte)0xC3, 
            (byte)0x59, (byte)0xA9, (byte)0xD4, (byte)0x1A, 
            (byte)0x22, (byte)0xFC, (byte)0xCD, (byte)0x91, 
            (byte)0x08, (byte)0xE1, (byte)0x7B, (byte)0xF7, 
            (byte)0xBA, (byte)0x93, (byte)0x37, (byte)0xA6, 
            (byte)0xF8, (byte)0xAE, (byte)0x95, (byte)0x13    
        });
	    public static readonly Math.BigInteger SignX256A_P = new Math.BigInteger(1, new byte[] {  
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFD, (byte)0x97
        });
	    public static readonly Math.BigInteger SignX256A_Q = new Math.BigInteger(1, new byte[] { 
            (byte)0x40, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x0F, (byte)0xD8, (byte)0xCD, (byte)0xDF, 
            (byte)0xC8, (byte)0x7B, (byte)0x66, (byte)0x35, 
            (byte)0xC1, (byte)0x15, (byte)0xAF, (byte)0x55, 
            (byte)0x6C, (byte)0x36, (byte)0x0C, (byte)0x67
        });
	    public static readonly Math.BigInteger SignX256A_X = new Math.BigInteger(1, new byte[] { 
            (byte)0x91, (byte)0xE3, (byte)0x84, (byte)0x43, 
            (byte)0xA5, (byte)0xE8, (byte)0x2C, (byte)0x0D, 
            (byte)0x88, (byte)0x09, (byte)0x23, (byte)0x42, 
            (byte)0x57, (byte)0x12, (byte)0xB2, (byte)0xBB, 
            (byte)0x65, (byte)0x8B, (byte)0x91, (byte)0x96, 
            (byte)0x93, (byte)0x2E, (byte)0x02, (byte)0xC7, 
            (byte)0x8B, (byte)0x25, (byte)0x82, (byte)0xFE, 
            (byte)0x74, (byte)0x2D, (byte)0xAA, (byte)0x28
        });
	    public static readonly Math.BigInteger SignX256A_Y = new Math.BigInteger(1, new byte[] { 
            (byte)0x32, (byte)0x87, (byte)0x94, (byte)0x23, 
            (byte)0xAB, (byte)0x1A, (byte)0x03, (byte)0x75, 
            (byte)0x89, (byte)0x57, (byte)0x86, (byte)0xC4, 
            (byte)0xBB, (byte)0x46, (byte)0xE9, (byte)0x56, 
            (byte)0x5F, (byte)0xDE, (byte)0x0B, (byte)0x53, 
            (byte)0x44, (byte)0x76, (byte)0x67, (byte)0x40, 
            (byte)0xAF, (byte)0x26, (byte)0x8A, (byte)0xDB, 
            (byte)0x32, (byte)0x32, (byte)0x2E, (byte)0x5C
        }); 
	    // параметры алгоритма
	    public static readonly Math.BigInteger SignX512T_A = new Math.BigInteger(1, new byte[] { 0x07 }); 
	    public static readonly Math.BigInteger SignX512T_B = new Math.BigInteger(1, new byte[] { 
            (byte)0x1C, (byte)0xFF, (byte)0x08, (byte)0x06, 
            (byte)0xA3, (byte)0x11, (byte)0x16, (byte)0xDA, 
            (byte)0x29, (byte)0xD8, (byte)0xCF, (byte)0xA5, 
            (byte)0x4E, (byte)0x57, (byte)0xEB, (byte)0x74, 
            (byte)0x8B, (byte)0xC5, (byte)0xF3, (byte)0x77, 
            (byte)0xE4, (byte)0x94, (byte)0x00, (byte)0xFD, 
            (byte)0xD7, (byte)0x88, (byte)0xB6, (byte)0x49, 
            (byte)0xEC, (byte)0xA1, (byte)0xAC, (byte)0x43, 
            (byte)0x61, (byte)0x83, (byte)0x40, (byte)0x13, 
            (byte)0xB2, (byte)0xAD, (byte)0x73, (byte)0x22, 
            (byte)0x48, (byte)0x0A, (byte)0x89, (byte)0xCA, 
            (byte)0x58, (byte)0xE0, (byte)0xCF, (byte)0x74, 
            (byte)0xBC, (byte)0x9E, (byte)0x54, (byte)0x0C, 
            (byte)0x2A, (byte)0xDD, (byte)0x68, (byte)0x97, 
            (byte)0xFA, (byte)0xD0, (byte)0xA3, (byte)0x08, 
            (byte)0x4F, (byte)0x30, (byte)0x2A, (byte)0xDC
        });
	    public static readonly Math.BigInteger SignX512T_P = new Math.BigInteger(1, new byte[] { 
            (byte)0x45, (byte)0x31, (byte)0xAC, (byte)0xD1, 
            (byte)0xFE, (byte)0x00, (byte)0x23, (byte)0xC7, 
            (byte)0x55, (byte)0x0D, (byte)0x26, (byte)0x7B, 
            (byte)0x6B, (byte)0x2F, (byte)0xEE, (byte)0x80, 
            (byte)0x92, (byte)0x2B, (byte)0x14, (byte)0xB2, 
            (byte)0xFF, (byte)0xB9, (byte)0x0F, (byte)0x04, 
            (byte)0xD4, (byte)0xEB, (byte)0x7C, (byte)0x09, 
            (byte)0xB5, (byte)0xD2, (byte)0xD1, (byte)0x5D,
            (byte)0xF1, (byte)0xD8, (byte)0x52, (byte)0x74, 
            (byte)0x1A, (byte)0xF4, (byte)0x70, (byte)0x4A, 
            (byte)0x04, (byte)0x58, (byte)0x04, (byte)0x7E, 
            (byte)0x80, (byte)0xE4, (byte)0x54, (byte)0x6D, 
            (byte)0x35, (byte)0xB8, (byte)0x33, (byte)0x6F, 
            (byte)0xAC, (byte)0x22, (byte)0x4D, (byte)0xD8, 
            (byte)0x16, (byte)0x64, (byte)0xBB, (byte)0xF5, 
            (byte)0x28, (byte)0xBE, (byte)0x63, (byte)0x73
	    });
	    public static readonly Math.BigInteger SignX512T_Q = new Math.BigInteger(1, new byte[] { 
            (byte)0x45, (byte)0x31, (byte)0xAC, (byte)0xD1, 
            (byte)0xFE, (byte)0x00, (byte)0x23, (byte)0xC7, 
            (byte)0x55, (byte)0x0D, (byte)0x26, (byte)0x7B, 
            (byte)0x6B, (byte)0x2F, (byte)0xEE, (byte)0x80, 
            (byte)0x92, (byte)0x2B, (byte)0x14, (byte)0xB2, 
            (byte)0xFF, (byte)0xB9, (byte)0x0F, (byte)0x04, 
            (byte)0xD4, (byte)0xEB, (byte)0x7C, (byte)0x09, 
            (byte)0xB5, (byte)0xD2, (byte)0xD1, (byte)0x5D, 
            (byte)0xA8, (byte)0x2F, (byte)0x2D, (byte)0x7E, 
            (byte)0xCB, (byte)0x1D, (byte)0xBA, (byte)0xC7, 
            (byte)0x19, (byte)0x90, (byte)0x5C, (byte)0x5E, 
            (byte)0xEC, (byte)0xC4, (byte)0x23, (byte)0xF1, 
            (byte)0xD8, (byte)0x6E, (byte)0x25, (byte)0xED, 
            (byte)0xBE, (byte)0x23, (byte)0xC5, (byte)0x95, 
            (byte)0xD6, (byte)0x44, (byte)0xAA, (byte)0xF1, 
            (byte)0x87, (byte)0xE6, (byte)0xE6, (byte)0xDF
	    });
	    public static readonly Math.BigInteger SignX512T_X = new Math.BigInteger(1, new byte[] { 
            (byte)0x24, (byte)0xD1, (byte)0x9C, (byte)0xC6, 
            (byte)0x45, (byte)0x72, (byte)0xEE, (byte)0x30, 
            (byte)0xF3, (byte)0x96, (byte)0xBF, (byte)0x6E, 
            (byte)0xBB, (byte)0xFD, (byte)0x7A, (byte)0x6C, 
            (byte)0x52, (byte)0x13, (byte)0xB3, (byte)0xB3, 
            (byte)0xD7, (byte)0x05, (byte)0x7C, (byte)0xC8, 
            (byte)0x25, (byte)0xF9, (byte)0x10, (byte)0x93, 
            (byte)0xA6, (byte)0x8C, (byte)0xD7, (byte)0x62,
            (byte)0xFD, (byte)0x60, (byte)0x61, (byte)0x12, 
            (byte)0x62, (byte)0xCD, (byte)0x83, (byte)0x8D, 
            (byte)0xC6, (byte)0xB6, (byte)0x0A, (byte)0xA7, 
            (byte)0xEE, (byte)0xE8, (byte)0x04, (byte)0xE2, 
            (byte)0x8B, (byte)0xC8, (byte)0x49, (byte)0x97, 
            (byte)0x7F, (byte)0xAC, (byte)0x33, (byte)0xB4, 
            (byte)0xB5, (byte)0x30, (byte)0xF1, (byte)0xB1, 
            (byte)0x20, (byte)0x24, (byte)0x8A, (byte)0x9A
        });
	    public static readonly Math.BigInteger SignX512T_Y = new Math.BigInteger(1, new byte[] { 
            (byte)0x2B, (byte)0xB3, (byte)0x12, (byte)0xA4, 
            (byte)0x3B, (byte)0xD2, (byte)0xCE, (byte)0x6E, 
            (byte)0x0D, (byte)0x02, (byte)0x06, (byte)0x13, 
            (byte)0xC8, (byte)0x57, (byte)0xAC, (byte)0xDD, 
            (byte)0xCF, (byte)0xBF, (byte)0x06, (byte)0x1E, 
            (byte)0x91, (byte)0xE5, (byte)0xF2, (byte)0xC3, 
            (byte)0xF3, (byte)0x24, (byte)0x47, (byte)0xC2, 
            (byte)0x59, (byte)0xF3, (byte)0x9B, (byte)0x2C, 
            (byte)0x83, (byte)0xAB, (byte)0x15, (byte)0x6D, 
            (byte)0x77, (byte)0xF1, (byte)0x49, (byte)0x6B, 
            (byte)0xF7, (byte)0xEB, (byte)0x33, (byte)0x51, 
            (byte)0xE1, (byte)0xEE, (byte)0x4E, (byte)0x43, 
            (byte)0xDC, (byte)0x1A, (byte)0x18, (byte)0xB9, 
            (byte)0x1B, (byte)0x24, (byte)0x64, (byte)0x0B, 
            (byte)0x6D, (byte)0xBB, (byte)0x92, (byte)0xCB, 
            (byte)0x1A, (byte)0xDD, (byte)0x37, (byte)0x1E
        }); 
	    // параметры алгоритма
	    public static readonly Math.BigInteger SignX512A_A = new Math.BigInteger(1, new byte[] { 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFD, (byte)0xC4 
	    });
	    public static readonly Math.BigInteger SignX512A_B = new Math.BigInteger(1, new byte[] { 
            (byte)0xE8, (byte)0xC2, (byte)0x50, (byte)0x5D, 
            (byte)0xED, (byte)0xFC, (byte)0x86, (byte)0xDD, 
            (byte)0xC1, (byte)0xBD, (byte)0x0B, (byte)0x2B, 
            (byte)0x66, (byte)0x67, (byte)0xF1, (byte)0xDA, 
            (byte)0x34, (byte)0xB8, (byte)0x25, (byte)0x74, 
            (byte)0x76, (byte)0x1C, (byte)0xB0, (byte)0xE8, 
            (byte)0x79, (byte)0xBD, (byte)0x08, (byte)0x1C, 
            (byte)0xFD, (byte)0x0B, (byte)0x62, (byte)0x65, 
            (byte)0xEE, (byte)0x3C, (byte)0xB0, (byte)0x90, 
            (byte)0xF3, (byte)0x0D, (byte)0x27, (byte)0x61, 
            (byte)0x4C, (byte)0xB4, (byte)0x57, (byte)0x40, 
            (byte)0x10, (byte)0xDA, (byte)0x90, (byte)0xDD, 
            (byte)0x86, (byte)0x2E, (byte)0xF9, (byte)0xD4, 
            (byte)0xEB, (byte)0xEE, (byte)0x47, (byte)0x61, 
            (byte)0x50, (byte)0x31, (byte)0x90, (byte)0x78, 
            (byte)0x5A, (byte)0x71, (byte)0xC7, (byte)0x60
        });
	    public static readonly Math.BigInteger SignX512A_P = new Math.BigInteger(1, new byte[] { 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFD, (byte)0xC7
	    });
	    public static readonly Math.BigInteger SignX512A_Q = new Math.BigInteger(1, new byte[] { 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0x27, (byte)0xE6, (byte)0x95, (byte)0x32, 
            (byte)0xF4, (byte)0x8D, (byte)0x89, (byte)0x11, 
            (byte)0x6F, (byte)0xF2, (byte)0x2B, (byte)0x8D, 
            (byte)0x4E, (byte)0x05, (byte)0x60, (byte)0x60, 
            (byte)0x9B, (byte)0x4B, (byte)0x38, (byte)0xAB, 
            (byte)0xFA, (byte)0xD2, (byte)0xB8, (byte)0x5D, 
            (byte)0xCA, (byte)0xCD, (byte)0xB1, (byte)0x41, 
            (byte)0x1F, (byte)0x10, (byte)0xB2, (byte)0x75
	    });
	    public static readonly Math.BigInteger SignX512A_X = new Math.BigInteger(1, new byte[] { (byte)0x03 });
	    public static readonly Math.BigInteger SignX512A_Y = new Math.BigInteger(1, new byte[] { 
            (byte)0x75, (byte)0x03, (byte)0xCF, (byte)0xE8, 
            (byte)0x7A, (byte)0x83, (byte)0x6A, (byte)0xE3, 
            (byte)0xA6, (byte)0x1B, (byte)0x88, (byte)0x16, 
            (byte)0xE2, (byte)0x54, (byte)0x50, (byte)0xE6, 
            (byte)0xCE, (byte)0x5E, (byte)0x1C, (byte)0x93, 
            (byte)0xAC, (byte)0xF1, (byte)0xAB, (byte)0xC1, 
            (byte)0x77, (byte)0x80, (byte)0x64, (byte)0xFD, 
            (byte)0xCB, (byte)0xEF, (byte)0xA9, (byte)0x21, 
            (byte)0xDF, (byte)0x16, (byte)0x26, (byte)0xBE, 
            (byte)0x4F, (byte)0xD0, (byte)0x36, (byte)0xE9, 
            (byte)0x3D, (byte)0x75, (byte)0xE6, (byte)0xA5, 
            (byte)0x0E, (byte)0x3A, (byte)0x41, (byte)0xE9, 
            (byte)0x80, (byte)0x28, (byte)0xFE, (byte)0x5F, 
            (byte)0xC2, (byte)0x35, (byte)0xF5, (byte)0xB8, 
            (byte)0x89, (byte)0xA5, (byte)0x89, (byte)0xCB, 
            (byte)0x52, (byte)0x15, (byte)0xF2, (byte)0xA4		
        }); 
	    // параметры алгоритма
	    public static readonly Math.BigInteger SignX512B_A = new Math.BigInteger(1, new byte[] { 
            (byte)0x80, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x6C		
        });
	    public static readonly Math.BigInteger SignX512B_B = new Math.BigInteger(1, new byte[] { 
            (byte)0x68, (byte)0x7D, (byte)0x1B, (byte)0x45, 
            (byte)0x9D, (byte)0xC8, (byte)0x41, (byte)0x45, 
            (byte)0x7E, (byte)0x3E, (byte)0x06, (byte)0xCF, 
            (byte)0x6F, (byte)0x5E, (byte)0x25, (byte)0x17, 
            (byte)0xB9, (byte)0x7C, (byte)0x7D, (byte)0x61, 
            (byte)0x4A, (byte)0xF1, (byte)0x38, (byte)0xBC, 
            (byte)0xBF, (byte)0x85, (byte)0xDC, (byte)0x80, 
            (byte)0x6C, (byte)0x4B, (byte)0x28, (byte)0x9F, 
            (byte)0x3E, (byte)0x96, (byte)0x5D, (byte)0x2D, 
            (byte)0xB1, (byte)0x41, (byte)0x6D, (byte)0x21, 
            (byte)0x7F, (byte)0x8B, (byte)0x27, (byte)0x6F, 
            (byte)0xAD, (byte)0x1A, (byte)0xB6, (byte)0x9C, 
            (byte)0x50, (byte)0xF7, (byte)0x8B, (byte)0xEE, 
            (byte)0x1F, (byte)0xA3, (byte)0x10, (byte)0x6E, 
            (byte)0xFB, (byte)0x8C, (byte)0xCB, (byte)0xC7, 
            (byte)0xC5, (byte)0x14, (byte)0x01, (byte)0x16        
        });
	    public static readonly Math.BigInteger SignX512B_P = new Math.BigInteger(1, new byte[] { 
            (byte)0x80, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x6F		
	    });
	    public static readonly Math.BigInteger SignX512B_Q = new Math.BigInteger(1, new byte[] { 
            (byte)0x80, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x01, 
            (byte)0x49, (byte)0xA1, (byte)0xEC, (byte)0x14, 
            (byte)0x25, (byte)0x65, (byte)0xA5, (byte)0x45, 
            (byte)0xAC, (byte)0xFD, (byte)0xB7, (byte)0x7B, 
            (byte)0xD9, (byte)0xD4, (byte)0x0C, (byte)0xFA, 
            (byte)0x8B, (byte)0x99, (byte)0x67, (byte)0x12, 
            (byte)0x10, (byte)0x1B, (byte)0xEA, (byte)0x0E, 
            (byte)0xC6, (byte)0x34, (byte)0x6C, (byte)0x54, 
            (byte)0x37, (byte)0x4F, (byte)0x25, (byte)0xBD
	    });
	    public static readonly Math.BigInteger SignX512B_X = new Math.BigInteger(1, new byte[] { (byte)0x02 });
	    public static readonly Math.BigInteger SignX512B_Y = new Math.BigInteger(1, new byte[] { 
            (byte)0x1A, (byte)0x8F, (byte)0x7E, (byte)0xDA, 
            (byte)0x38, (byte)0x9B, (byte)0x09, (byte)0x4C, 
            (byte)0x2C, (byte)0x07, (byte)0x1E, (byte)0x36, 
            (byte)0x47, (byte)0xA8, (byte)0x94, (byte)0x0F, 
            (byte)0x3C, (byte)0x12, (byte)0x3B, (byte)0x69, 
            (byte)0x75, (byte)0x78, (byte)0xC2, (byte)0x13, 
            (byte)0xBE, (byte)0x6D, (byte)0xD9, (byte)0xE6, 
            (byte)0xC8, (byte)0xEC, (byte)0x73, (byte)0x35, 
            (byte)0xDC, (byte)0xB2, (byte)0x28, (byte)0xFD, 
            (byte)0x1E, (byte)0xDF, (byte)0x4A, (byte)0x39, 
            (byte)0x15, (byte)0x2C, (byte)0xBC, (byte)0xAA, 
            (byte)0xF8, (byte)0xC0, (byte)0x39, (byte)0x88, 
            (byte)0x28, (byte)0x04, (byte)0x10, (byte)0x55, 
            (byte)0xF9, (byte)0x4C, (byte)0xEE, (byte)0xEC, 
            (byte)0x7E, (byte)0x21, (byte)0x34, (byte)0x07, 
            (byte)0x80, (byte)0xFE, (byte)0x41, (byte)0xBD
        }); 
	    // параметры алгоритма
	    public static readonly Math.BigInteger SignX512C_A = new Math.BigInteger(1, new byte[] { 
            (byte)0xDC, (byte)0x92, (byte)0x03, (byte)0xE5, 
            (byte)0x14, (byte)0xA7, (byte)0x21, (byte)0x87, 
            (byte)0x54, (byte)0x85, (byte)0xA5, (byte)0x29, 
            (byte)0xD2, (byte)0xC7, (byte)0x22, (byte)0xFB, 
            (byte)0x18, (byte)0x7B, (byte)0xC8, (byte)0x98, 
            (byte)0x0E, (byte)0xB8, (byte)0x66, (byte)0x64, 
            (byte)0x4D, (byte)0xE4, (byte)0x1C, (byte)0x68, 
            (byte)0xE1, (byte)0x43, (byte)0x06, (byte)0x45, 
            (byte)0x46, (byte)0xE8, (byte)0x61, (byte)0xC0, 
            (byte)0xE2, (byte)0xC9, (byte)0xED, (byte)0xD9, 
            (byte)0x2A, (byte)0xDE, (byte)0x71, (byte)0xF4, 
            (byte)0x6F, (byte)0xCF, (byte)0x50, (byte)0xFF, 
            (byte)0x2A, (byte)0xD9, (byte)0x7F, (byte)0x95, 
            (byte)0x1F, (byte)0xDA, (byte)0x9F, (byte)0x2A, 
            (byte)0x2E, (byte)0xB6, (byte)0x54, (byte)0x6F, 
            (byte)0x39, (byte)0x68, (byte)0x9B, (byte)0xD3
        });
	    public static readonly Math.BigInteger SignX512C_B = new Math.BigInteger(1, new byte[] { 
            (byte)0xB4, (byte)0xC4, (byte)0xEE, (byte)0x28, 
            (byte)0xCE, (byte)0xBC, (byte)0x6C, (byte)0x2C, 
            (byte)0x8A, (byte)0xC1, (byte)0x29, (byte)0x52, 
            (byte)0xCF, (byte)0x37, (byte)0xF1, (byte)0x6A, 
            (byte)0xC7, (byte)0xEF, (byte)0xB6, (byte)0xA9, 
            (byte)0xF6, (byte)0x9F, (byte)0x4B, (byte)0x57, 
            (byte)0xFF, (byte)0xDA, (byte)0x2E, (byte)0x4F, 
            (byte)0x0D, (byte)0xE5, (byte)0xAD, (byte)0xE0, 
            (byte)0x38, (byte)0xCB, (byte)0xC2, (byte)0xFF, 
            (byte)0xF7, (byte)0x19, (byte)0xD2, (byte)0xC1,
            (byte)0x8D, (byte)0xE0, (byte)0x28, (byte)0x4B, 
            (byte)0x8B, (byte)0xFE, (byte)0xF3, (byte)0xB5, 
            (byte)0x2B, (byte)0x8C, (byte)0xC7, (byte)0xA5, 
            (byte)0xF5, (byte)0xBF, (byte)0x0A, (byte)0x3C, 
            (byte)0x8D, (byte)0x23, (byte)0x19, (byte)0xA5, 
            (byte)0x31, (byte)0x25, (byte)0x57, (byte)0xE1
        });
	    public static readonly Math.BigInteger SignX512C_P = new Math.BigInteger(1, new byte[] { 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFD, (byte)0xC7
        });
	    public static readonly Math.BigInteger SignX512C_Q = new Math.BigInteger(1, new byte[] { 
            (byte)0x3F, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xC9, (byte)0x8C, (byte)0xDB, (byte)0xA4, 
            (byte)0x65, (byte)0x06, (byte)0xAB, (byte)0x00, 
            (byte)0x4C, (byte)0x33, (byte)0xA9, (byte)0xFF, 
            (byte)0x51, (byte)0x47, (byte)0x50, (byte)0x2C, 
            (byte)0xC8, (byte)0xED, (byte)0xA9, (byte)0xE7, 
            (byte)0xA7, (byte)0x69, (byte)0xA1, (byte)0x26, 
            (byte)0x94, (byte)0x62, (byte)0x3C, (byte)0xEF, 
            (byte)0x47, (byte)0xF0, (byte)0x23, (byte)0xED
        });
	    public static readonly Math.BigInteger SignX512C_X = new Math.BigInteger(1, new byte[] { 
            (byte)0xE2, (byte)0xE3, (byte)0x1E, (byte)0xDF, 
            (byte)0xC2, (byte)0x3D, (byte)0xE7, (byte)0xBD, 
            (byte)0xEB, (byte)0xE2, (byte)0x41, (byte)0xCE, 
            (byte)0x59, (byte)0x3E, (byte)0xF5, (byte)0xDE, 
            (byte)0x22, (byte)0x95, (byte)0xB7, (byte)0xA9, 
            (byte)0xCB, (byte)0xAE, (byte)0xF0, (byte)0x21, 
            (byte)0xD3, (byte)0x85, (byte)0xF7, (byte)0x07, 
            (byte)0x4C, (byte)0xEA, (byte)0x04, (byte)0x3A, 
            (byte)0xA2, (byte)0x72, (byte)0x72, (byte)0xA7, 
            (byte)0xAE, (byte)0x60, (byte)0x2B, (byte)0xF2, 
            (byte)0xA7, (byte)0xB9, (byte)0x03, (byte)0x3D, 
            (byte)0xB9, (byte)0xED, (byte)0x36, (byte)0x10, 
            (byte)0xC6, (byte)0xFB, (byte)0x85, (byte)0x48, 
            (byte)0x7E, (byte)0xAE, (byte)0x97, (byte)0xAA, 
            (byte)0xC5, (byte)0xBC, (byte)0x79, (byte)0x28, 
            (byte)0xC1, (byte)0x95, (byte)0x01, (byte)0x48
        });
	    public static readonly Math.BigInteger SignX512C_Y = new Math.BigInteger(1, new byte[] { 
            (byte)0xF5, (byte)0xCE, (byte)0x40, (byte)0xD9, 
            (byte)0x5B, (byte)0x5E, (byte)0xB8, (byte)0x99, 
            (byte)0xAB, (byte)0xBC, (byte)0xCF, (byte)0xF5, 
            (byte)0x91, (byte)0x1C, (byte)0xB8, (byte)0x57, 
            (byte)0x79, (byte)0x39, (byte)0x80, (byte)0x4D, 
            (byte)0x65, (byte)0x27, (byte)0x37, (byte)0x8B, 
            (byte)0x8C, (byte)0x10, (byte)0x8C, (byte)0x3D, 
            (byte)0x20, (byte)0x90, (byte)0xFF, (byte)0x9B, 
            (byte)0xE1, (byte)0x8E, (byte)0x2D, (byte)0x33, 
            (byte)0xE3, (byte)0x02, (byte)0x1E, (byte)0xD2, 
            (byte)0xEF, (byte)0x32, (byte)0xD8, (byte)0x58, 
            (byte)0x22, (byte)0x42, (byte)0x3B, (byte)0x63, 
            (byte)0x04, (byte)0xF7, (byte)0x26, (byte)0xAA, 
            (byte)0x85, (byte)0x4B, (byte)0xAE, (byte)0x07, 
            (byte)0xD0, (byte)0x39, (byte)0x6E, (byte)0x9A, 
            (byte)0x9A, (byte)0xDD, (byte)0xC4, (byte)0x0F
        }); 
	    // таблица именованных параметров
	    private static readonly Dictionary<String, GOSTR3410ParamSet> set = 
		    new Dictionary<String, GOSTR3410ParamSet>(); 
	    static GOSTR3410ParamSet()
        {
		    set.Add(OID.ecc_signs_test	, new GOSTR3410ParamSet(
			    new Integer(Sign256T_A), new Integer(Sign256T_B), 
                new Integer(Sign256T_P), new Integer(Sign256T_Q), 
                new Integer(Sign256T_X), new Integer(Sign256T_Y)
		    )); 
		    set.Add(OID.ecc_signs_A		, new GOSTR3410ParamSet(
			    new Integer(Sign256A_A), new Integer(Sign256A_B), 
                new Integer(Sign256A_P), new Integer(Sign256A_Q), 
                new Integer(Sign256A_X), new Integer(Sign256A_Y)
		    )); 
		    set.Add(OID.ecc_signs_B		, new GOSTR3410ParamSet(
			    new Integer(Sign256B_A), new Integer(Sign256B_B), 
                new Integer(Sign256B_P), new Integer(Sign256B_Q), 
                new Integer(Sign256B_X), new Integer(Sign256B_Y)
		    )); 
		    set.Add(OID.ecc_signs_C		, new GOSTR3410ParamSet(
			    new Integer(Sign256C_A), new Integer(Sign256C_B), 
                new Integer(Sign256C_P), new Integer(Sign256C_Q), 
                new Integer(Sign256C_X), new Integer(Sign256C_Y)
		    )); 
		    set.Add(OID.ecc_exchanges_A , new GOSTR3410ParamSet(
			    new Integer(Keyx256A_A), new Integer(Keyx256A_B), 
                new Integer(Keyx256A_P), new Integer(Keyx256A_Q), 
                new Integer(Keyx256A_X), new Integer(Keyx256A_Y)
		    )); 
		    set.Add(OID.ecc_exchanges_B , new GOSTR3410ParamSet(
			    new Integer(Keyx256B_A), new Integer(Keyx256B_B), 
                new Integer(Keyx256B_P), new Integer(Keyx256B_Q), 
                new Integer(Keyx256B_X), new Integer(Keyx256B_Y)
		    )); 
            set.Add(OID.ecc_tc26_2012_256A, new GOSTR3410ParamSet(
                new Integer(SignX256A_A), new Integer(SignX256A_B), 
                new Integer(SignX256A_P), new Integer(SignX256A_Q), 
                new Integer(SignX256A_X), new Integer(SignX256A_Y)
		    )); 
            set.Add(OID.ecc_tc26_2012_512T, new GOSTR3410ParamSet(
                new Integer(SignX512T_A), new Integer(SignX512T_B), 
                new Integer(SignX512T_P), new Integer(SignX512T_Q), 
                new Integer(SignX512T_X), new Integer(SignX512T_Y)
		    )); 
            set.Add(OID.ecc_tc26_2012_512A , new GOSTR3410ParamSet(
                new Integer(SignX512A_A), new Integer(SignX512A_B), 
                new Integer(SignX512A_P), new Integer(SignX512A_Q), 
                new Integer(SignX512A_X), new Integer(SignX512A_Y)
		    )); 
		    set.Add(OID.ecc_tc26_2012_512B , new GOSTR3410ParamSet(
			    new Integer(SignX512B_A), new Integer(SignX512B_B), 
                new Integer(SignX512B_P), new Integer(SignX512B_Q), 
                new Integer(SignX512B_X), new Integer(SignX512B_Y)
		    )); 
		    set.Add(OID.ecc_tc26_2012_512C , new GOSTR3410ParamSet(
			    new Integer(SignX512C_A), new Integer(SignX512C_B), 
                new Integer(SignX512C_P), new Integer(SignX512C_Q), 
                new Integer(SignX512C_X), new Integer(SignX512C_Y)
		    )); 
	    }
	    // получить именованные параметры
	    public static GOSTR3410ParamSet Parameters(string oid) { return set[oid]; } 
	}
}
