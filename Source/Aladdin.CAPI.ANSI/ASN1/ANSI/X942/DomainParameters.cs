﻿using System;
using System.Runtime.Serialization;

// DomainParameters ::= SEQUENCE {
//		p					INTEGER, 
//		g					INTEGER, 
//		q					INTEGER, 
//		j					INTEGER OPTIONAL, 
//		validationParms		ValidationParms OPTIONAL 
// }

namespace Aladdin.ASN1.ANSI.X942
{
	[Serializable]
	public class DomainParameters : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<Integer		>().Factory(), Cast.N), 
			new ObjectInfo(new ObjectCreator<Integer		>().Factory(), Cast.N), 
			new ObjectInfo(new ObjectCreator<Integer		>().Factory(), Cast.N), 
			new ObjectInfo(new ObjectCreator<Integer		>().Factory(), Cast.O), 
			new ObjectInfo(new ObjectCreator<ValidationParms>().Factory(), Cast.O), 
		}; 
		// конструктор при сериализации
        protected DomainParameters(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public DomainParameters(IEncodable encodable) : base(encodable, info) {}

		// конструктор при закодировании
		public DomainParameters(Integer p, Integer g, Integer q, Integer j, 
			ValidationParms validationParms) : base(info, p, g, q, j, validationParms) {}

		public Integer			P			{ get { return (Integer			)this[0]; } }
		public Integer			G			{ get { return (Integer			)this[1]; } }
		public Integer			Q			{ get { return (Integer			)this[2]; } }
		public Integer			J			{ get { return (Integer			)this[3]; } }
		public ValidationParms	Parameters	{ get { return (ValidationParms )this[4]; } }

        ////////////////////////////////////////////////////////////////////////////
        // Наборы параметров
        ////////////////////////////////////////////////////////////////////////////
	    private static readonly Math.BigInteger Ephemeral_P = 
            new Math.BigInteger(1, new byte[] {
		    (byte)0xD7, (byte)0x57, (byte)0x26, (byte)0x2C, 
            (byte)0x45, (byte)0x84, (byte)0xC4, (byte)0x4C,
		    (byte)0x21, (byte)0x1F, (byte)0x18, (byte)0xBD, 
            (byte)0x96, (byte)0xE5, (byte)0xF0, (byte)0x61,
		    (byte)0xC4, (byte)0xF0, (byte)0xA4, (byte)0x23, 
            (byte)0xF7, (byte)0xFE, (byte)0x6B, (byte)0x6B, 
		    (byte)0x85, (byte)0xB3, (byte)0x4C, (byte)0xEF, 
            (byte)0x72, (byte)0xCE, (byte)0x14, (byte)0xA0,
		    (byte)0xD3, (byte)0xA5, (byte)0x22, (byte)0x2F, 
            (byte)0xE0, (byte)0x8C, (byte)0xEC, (byte)0xE6, 
		    (byte)0x5B, (byte)0xE6, (byte)0xC2, (byte)0x65, 
            (byte)0x85, (byte)0x48, (byte)0x89, (byte)0xDC,
		    (byte)0x1E, (byte)0xDB, (byte)0xD1, (byte)0x3E, 
            (byte)0xC8, (byte)0xB2, (byte)0x74, (byte)0xDA, 
		    (byte)0x9F, (byte)0x75, (byte)0xBA, (byte)0x26, 
            (byte)0xCC, (byte)0xB9, (byte)0x87, (byte)0x72,
		    (byte)0x36, (byte)0x02, (byte)0x78, (byte)0x7E, 
            (byte)0x92, (byte)0x2B, (byte)0xA8, (byte)0x44, 
		    (byte)0x21, (byte)0xF2, (byte)0x2C, (byte)0x3C, 
            (byte)0x89, (byte)0xCB, (byte)0x9B, (byte)0x06,
		    (byte)0xFD, (byte)0x60, (byte)0xFE, (byte)0x01, 
            (byte)0x94, (byte)0x1D, (byte)0xDD, (byte)0x77, 
		    (byte)0xFE, (byte)0x6B, (byte)0x12, (byte)0x89, 
            (byte)0x3D, (byte)0xA7, (byte)0x6E, (byte)0xEB,
		    (byte)0xC1, (byte)0xD1, (byte)0x28, (byte)0xD9, 
            (byte)0x7F, (byte)0x06, (byte)0x78, (byte)0xD7, 
		    (byte)0x72, (byte)0x2B, (byte)0x53, (byte)0x41, 
            (byte)0xC8, (byte)0x50, (byte)0x6F, (byte)0x35,
		    (byte)0x82, (byte)0x14, (byte)0xB1, (byte)0x6A, 
            (byte)0x2F, (byte)0xAC, (byte)0x4B, (byte)0x36, 
		    (byte)0x89, (byte)0x50, (byte)0x38, (byte)0x78, 
            (byte)0x11, (byte)0xC7, (byte)0xDA, (byte)0x33,
	    });
	    private static readonly Math.BigInteger Ephemeral_G = 
            new Math.BigInteger(1, new byte[] {
		    (byte)0x82, (byte)0x26, (byte)0x90, (byte)0x09, 
            (byte)0xE1, (byte)0x4E, (byte)0xC4, (byte)0x74, 
		    (byte)0xBA, (byte)0xF2, (byte)0x93, (byte)0x2E, 
            (byte)0x69, (byte)0xD3, (byte)0xB1, (byte)0xF1,
		    (byte)0x85, (byte)0x17, (byte)0xAD, (byte)0x95, 
            (byte)0x94, (byte)0x18, (byte)0x4C, (byte)0xCD, 
		    (byte)0xFC, (byte)0xEA, (byte)0xE9, (byte)0x6E, 
            (byte)0xC4, (byte)0xD5, (byte)0xEF, (byte)0x93,
		    (byte)0x13, (byte)0x3E, (byte)0x84, (byte)0xB4, 
            (byte)0x70, (byte)0x93, (byte)0xC5, (byte)0x2B, 
		    (byte)0x20, (byte)0xCD, (byte)0x35, (byte)0xD0, 
            (byte)0x24, (byte)0x92, (byte)0xB3, (byte)0x95,
		    (byte)0x9E, (byte)0xC6, (byte)0x49, (byte)0x96, 
            (byte)0x25, (byte)0xBC, (byte)0x4F, (byte)0xA5, 
		    (byte)0x08, (byte)0x2E, (byte)0x22, (byte)0xC5, 
            (byte)0xB3, (byte)0x74, (byte)0xE1, (byte)0x6D,
		    (byte)0xD0, (byte)0x01, (byte)0x32, (byte)0xCE, 
            (byte)0x71, (byte)0xB0, (byte)0x20, (byte)0x21, 
		    (byte)0x70, (byte)0x91, (byte)0xAC, (byte)0x71, 
            (byte)0x7B, (byte)0x61, (byte)0x23, (byte)0x91,
		    (byte)0xC7, (byte)0x6C, (byte)0x1F, (byte)0xB2, 
            (byte)0xE8, (byte)0x83, (byte)0x17, (byte)0xC1, 
		    (byte)0xBD, (byte)0x81, (byte)0x71, (byte)0xD4, 
            (byte)0x1E, (byte)0xCB, (byte)0x83, (byte)0xE2,
		    (byte)0x10, (byte)0xC0, (byte)0x3C, (byte)0xC9, 
            (byte)0xB3, (byte)0x2E, (byte)0x81, (byte)0x05, 
		    (byte)0x61, (byte)0xC2, (byte)0x16, (byte)0x21, 
            (byte)0xC7, (byte)0x3D, (byte)0x6D, (byte)0xAA,
		    (byte)0xC0, (byte)0x28, (byte)0xF4, (byte)0xB1, 
            (byte)0x58, (byte)0x5D, (byte)0xA7, (byte)0xF4, 
		    (byte)0x25, (byte)0x19, (byte)0x71, (byte)0x8C, 
            (byte)0xC9, (byte)0xB0, (byte)0x9E, (byte)0xEF,
	    });
	    private static readonly Math.BigInteger Ephemeral_Q = 
            new Math.BigInteger(1, new byte[] {
		    (byte)0xC7, (byte)0x73, (byte)0x21, (byte)0x8C, 
            (byte)0x73, (byte)0x7E, (byte)0xC8, (byte)0xEE,
		    (byte)0x99, (byte)0x3B, (byte)0x4F, (byte)0x2D, 
            (byte)0xED, (byte)0x30, (byte)0xF4, (byte)0x8E,
		    (byte)0xDA, (byte)0xCE, (byte)0x91, (byte)0x5F		
	    });
	    private static readonly ASN1.BitString Ephemeral_Seed = 
            new ASN1.BitString(new byte[] {
		    (byte)0xd5, (byte)0x01, (byte)0x4e, (byte)0x4b, 
            (byte)0x60, (byte)0xef, (byte)0x2b, (byte)0xa8,
		    (byte)0xb6, (byte)0x21, (byte)0x1b, (byte)0x40, 
            (byte)0x62, (byte)0xba, (byte)0x32, (byte)0x24,
		    (byte)0xe0, (byte)0x42, (byte)0x7f, (byte)0x4f
	    });
	    // экземпляр параметров
	    public static readonly DomainParameters Ephemeral = new DomainParameters(
		    new Integer(Ephemeral_P), new Integer(Ephemeral_G), new Integer(Ephemeral_Q), 
            null, new ValidationParms(Ephemeral_Seed, new ASN1.Integer(371))
	    ); 
	    // именованные параметры
	    private static readonly Math.BigInteger Static_P = 
            new Math.BigInteger(1, new byte[] {
		    (byte)0xe0, (byte)0x01, (byte)0xe8, (byte)0x96, 
            (byte)0x7d, (byte)0xb4, (byte)0x93, (byte)0x53, 
		    (byte)0xe1, (byte)0x6f, (byte)0x8e, (byte)0x89, 
            (byte)0x22, (byte)0x0c, (byte)0xce, (byte)0xfc,
		    (byte)0x5c, (byte)0x5f, (byte)0x12, (byte)0xe3, 
            (byte)0xdf, (byte)0xf8, (byte)0xf1, (byte)0xd1, 
		    (byte)0x49, (byte)0x90, (byte)0x12, (byte)0xe6, 
            (byte)0xef, (byte)0x53, (byte)0xe3, (byte)0x1f,
		    (byte)0x02, (byte)0xea, (byte)0xcc, (byte)0x5a, 
            (byte)0xdd, (byte)0xf3, (byte)0x37, (byte)0x89, 
		    (byte)0x35, (byte)0xc9, (byte)0x5b, (byte)0x21, 
            (byte)0xea, (byte)0x3d, (byte)0x6f, (byte)0x1c,
		    (byte)0xd7, (byte)0xce, (byte)0x63, (byte)0x75, 
            (byte)0x52, (byte)0xec, (byte)0x38, (byte)0x6c, 
		    (byte)0x0e, (byte)0x34, (byte)0xf7, (byte)0x36, 
            (byte)0xad, (byte)0x95, (byte)0x17, (byte)0xef,
		    (byte)0xfe, (byte)0x5e, (byte)0x4d, (byte)0xa7, 
            (byte)0xa8, (byte)0x6a, (byte)0xf9, (byte)0x0e, 
		    (byte)0x2c, (byte)0x22, (byte)0x8f, (byte)0xe4, 
            (byte)0xb9, (byte)0xe6, (byte)0xd8, (byte)0xf8,
		    (byte)0xf0, (byte)0x2d, (byte)0x20, (byte)0xaf, 
            (byte)0x78, (byte)0xab, (byte)0xb6, (byte)0x92, 
		    (byte)0xac, (byte)0xbc, (byte)0x4b, (byte)0x23, 
            (byte)0xfa, (byte)0xf2, (byte)0xc5, (byte)0xcc,
		    (byte)0xd4, (byte)0x9a, (byte)0x0c, (byte)0x9a, 
            (byte)0x8b, (byte)0xcd, (byte)0x91, (byte)0xac, 
		    (byte)0x0c, (byte)0x55, (byte)0x92, (byte)0x01, 
            (byte)0xe6, (byte)0xc2, (byte)0xfd, (byte)0x1f,
		    (byte)0x47, (byte)0xc2, (byte)0xcb, (byte)0x2a, 
            (byte)0x88, (byte)0xa8, (byte)0x3c, (byte)0x21, 
		    (byte)0x0f, (byte)0xc0, (byte)0x54, (byte)0xdb, 
            (byte)0x29, (byte)0x2d, (byte)0xbc, (byte)0x45,
	    });
	    private static readonly Math.BigInteger Static_G = 
            new Math.BigInteger(1, new byte[] {
		    (byte)0x1c, (byte)0xe0, (byte)0xf6, (byte)0x69, 
            (byte)0x26, (byte)0x46, (byte)0x11, (byte)0x97,
		    (byte)0xef, (byte)0x45, (byte)0xc4, (byte)0x65, 
            (byte)0x8b, (byte)0x83, (byte)0xb8, (byte)0xab,
		    (byte)0x04, (byte)0xa9, (byte)0x22, (byte)0x42, 
            (byte)0x68, (byte)0x50, (byte)0x4d, (byte)0x05,
		    (byte)0xb8, (byte)0x19, (byte)0x83, (byte)0x99, 
            (byte)0xdd, (byte)0x71, (byte)0x37, (byte)0x18,
		    (byte)0xcc, (byte)0x1f, (byte)0x24, (byte)0x5d, 
            (byte)0x47, (byte)0x6c, (byte)0xcf, (byte)0x61,
		    (byte)0xa2, (byte)0xf9, (byte)0x34, (byte)0x93, 
            (byte)0xf4, (byte)0x1f, (byte)0x55, (byte)0x52,
		    (byte)0x48, (byte)0x65, (byte)0x57, (byte)0xe6, 
            (byte)0xd4, (byte)0xca, (byte)0xa8, (byte)0x00, 
		    (byte)0xd6, (byte)0xd0, (byte)0xdb, (byte)0x3c, 
            (byte)0xbf, (byte)0x5a, (byte)0x95, (byte)0x4b,
		    (byte)0x20, (byte)0x8a, (byte)0x4e, (byte)0xba, 
            (byte)0xf7, (byte)0xe6, (byte)0x49, (byte)0xfb, 
		    (byte)0x61, (byte)0x24, (byte)0xd8, (byte)0xa2, 
            (byte)0x1e, (byte)0xf2, (byte)0xf2, (byte)0x2b,
		    (byte)0xaa, (byte)0xae, (byte)0x29, (byte)0x21, 
            (byte)0x10, (byte)0x19, (byte)0x10, (byte)0x51, 
		    (byte)0x46, (byte)0x47, (byte)0x31, (byte)0xb6, 
            (byte)0xcc, (byte)0x3c, (byte)0x93, (byte)0xdc,
		    (byte)0x6e, (byte)0x80, (byte)0xba, (byte)0x16, 
            (byte)0x0b, (byte)0x66, (byte)0x64, (byte)0xa5, 
		    (byte)0x6c, (byte)0xfa, (byte)0x96, (byte)0xea, 
            (byte)0xf1, (byte)0xb2, (byte)0x83, (byte)0x39,
		    (byte)0x8e, (byte)0xb4, (byte)0x61, (byte)0x64, 
            (byte)0xe5, (byte)0xe9, (byte)0x43, (byte)0x84,
		    (byte)0xee, (byte)0x02, (byte)0x24, (byte)0xe7, 
            (byte)0x1f, (byte)0x03, (byte)0x7c, (byte)0x23,
	    });
	    private static readonly Math.BigInteger Static_Q = 
            new Math.BigInteger(1, new byte[] {
		    (byte)0x86, (byte)0x47, (byte)0x17, (byte)0xa3, 
            (byte)0x9e, (byte)0x6a, (byte)0xea, (byte)0x7e, 
		    (byte)0x89, (byte)0xc4, (byte)0x32, (byte)0xee, 
            (byte)0x77, (byte)0x43, (byte)0x15, (byte)0x16, 
		    (byte)0x96, (byte)0x77, (byte)0xc4, (byte)0x99
	    });
	    private static readonly ASN1.BitString Static_Seed = 
            new ASN1.BitString(new byte[] {
		    (byte)0xd5, (byte)0x01, (byte)0x4e, (byte)0x4b, 
            (byte)0x60, (byte)0xef, (byte)0x2b, (byte)0xa8, 
		    (byte)0xb6, (byte)0x21, (byte)0x1b, (byte)0x40, 
            (byte)0x62, (byte)0xba, (byte)0x32, (byte)0x24, 
		    (byte)0xe0, (byte)0x42, (byte)0x7d, (byte)0xd3
	    });
	    // экземпляр параметров
	    public static readonly DomainParameters Static = new DomainParameters(
		    new Integer(Static_P), new Integer(Static_G), new Integer(Static_Q), 
            null, new ValidationParms(Static_Seed, new Integer(246))
	    ); 
    }
}
