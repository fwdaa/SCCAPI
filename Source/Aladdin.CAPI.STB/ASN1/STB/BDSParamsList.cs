using System; 
using System.Collections.Generic;
using System.Runtime.Serialization;

namespace Aladdin.ASN1.STB
{
    ///////////////////////////////////////////////////////////////////////////////
    // BDSParamsList ::= SEQUENCE {
    // 		bdsParameterL [0] IMPLICIT INTEGER,
    // 		bdsParameterR [1] IMPLICIT INTEGER,
    // 		bdsParameterP [2] IMPLICIT INTEGER,
    // 		bdsParameterQ [3] IMPLICIT INTEGER,
    // 		bdsParameterA [4] IMPLICIT INTEGER,
    // 		bdsParameterH [5] IMPLICIT OCTET STRING,
    // 		bdsParamInitData BDSParamsInitData OPTIONAL
    // 	}
    ///////////////////////////////////////////////////////////////////////////////
    [Serializable]
    public class BDSParamsList : Sequence
    {
	    // информация о структуре
	    private static readonly ObjectInfo[] info = new ObjectInfo[] { 
        
		    new ObjectInfo(new ObjectCreator<Integer          >().Factory(), Cast.N, Tag.Context(0)), 
		    new ObjectInfo(new ObjectCreator<Integer          >().Factory(), Cast.N, Tag.Context(1)), 
		    new ObjectInfo(new ObjectCreator<Integer          >().Factory(), Cast.N, Tag.Context(2)), 
		    new ObjectInfo(new ObjectCreator<Integer          >().Factory(), Cast.N, Tag.Context(3)), 
		    new ObjectInfo(new ObjectCreator<Integer          >().Factory(), Cast.N, Tag.Context(4)), 
		    new ObjectInfo(new ObjectCreator<OctetString      >().Factory(), Cast.N, Tag.Context(5)), 
		    new ObjectInfo(new ObjectCreator<BDSParamsInitData>().Factory(), Cast.O, Tag.Any       ) 
	    }; 
		// конструктор при сериализации
        protected BDSParamsList(SerializationInfo info, StreamingContext context) : base(info, context) {}

	    // конструктор при раскодировании
	    public BDSParamsList(IEncodable encodable) : base(encodable, info) {}  
    
	    // конструктор при закодировании
	    public BDSParamsList(Integer bdsParameterL, Integer bdsParameterR, 
            Integer bdsParameterP, Integer bdsParameterQ, Integer bdsParameterA, 
            OctetString bdsParameterH, BDSParamsInitData bdsParamInitData)
		    : base(info, bdsParameterL, bdsParameterR, bdsParameterP, bdsParameterQ, 
                bdsParameterA, bdsParameterH, bdsParamInitData) {} 
	    
	    public Integer            BDSParameterL    { get { return (Integer            )this[0]; }}
	    public Integer            BDSParameterR    { get { return (Integer            )this[1]; }} 
	    public Integer            BDSParameterP    { get { return (Integer            )this[2]; }}
	    public Integer            BDSParameterQ    { get { return (Integer            )this[3]; }} 
	    public Integer            BDSParameterA    { get { return (Integer            )this[4]; }} 
	    public OctetString        BDSParameterH    { get { return (OctetString        )this[5]; }} 
	    public BDSParamsInitData  BDSParamInitData { get { return (BDSParamsInitData  )this[6]; }} 
    
	    ///////////////////////////////////////////////////////////////////////////
	    // Параметры алгоритма СТБ 1176.2-99 (уровень 3)
	    ///////////////////////////////////////////////////////////////////////////
        private static readonly Integer L3 = new Integer(1022); 
        private static readonly Integer R3 = new Integer(175 ); 
	    private static readonly Integer P3 = new Integer(
            new Math.BigInteger(1, new byte[] { 
                (byte)0x28, (byte)0x46, (byte)0xB9, (byte)0x79, 
                (byte)0xF5, (byte)0x1D, (byte)0x41, (byte)0x56, 
                (byte)0xB8, (byte)0x81, (byte)0xC9, (byte)0x6F, 
                (byte)0x3C, (byte)0x61, (byte)0xA5, (byte)0xF3, 
                (byte)0xB5, (byte)0xA8, (byte)0xF4, (byte)0xB4, 
                (byte)0x7B, (byte)0x60, (byte)0x46, (byte)0x57, 
                (byte)0x8B, (byte)0x92, (byte)0x20, (byte)0x5C, 
                (byte)0xA7, (byte)0xAD, (byte)0xCB, (byte)0x9A, 
                (byte)0x77, (byte)0xCF, (byte)0x77, (byte)0x80, 
                (byte)0x02, (byte)0x3B, (byte)0x72, (byte)0x17, 
                (byte)0x1B, (byte)0xB3, (byte)0xBE, (byte)0xD1, 
                (byte)0x56, (byte)0x9E, (byte)0xCA, (byte)0x57, 
                (byte)0x2C, (byte)0x5E, (byte)0x42, (byte)0x3B, 
                (byte)0x88, (byte)0x5C, (byte)0x70, (byte)0xF5, 
                (byte)0xD2, (byte)0xCD, (byte)0x3C, (byte)0x17, 
                (byte)0x0E, (byte)0x31, (byte)0xCE, (byte)0x50, 
                (byte)0x7D, (byte)0xE1, (byte)0x2C, (byte)0x9E, 
                (byte)0x53, (byte)0x5D, (byte)0x71, (byte)0xDA, 
                (byte)0x16, (byte)0x53, (byte)0x0C, (byte)0x9B, 
                (byte)0xE6, (byte)0xD0, (byte)0x78, (byte)0xC4, 
                (byte)0x67, (byte)0xCE, (byte)0x4D, (byte)0x24, 
                (byte)0xE7, (byte)0xC6, (byte)0x31, (byte)0x81, 
                (byte)0x7F, (byte)0xB4, (byte)0xBE, (byte)0x8F, 
                (byte)0x16, (byte)0xEB, (byte)0x1B, (byte)0x4D, 
                (byte)0xE7, (byte)0x15, (byte)0x2D, (byte)0xB1, 
                (byte)0x8B, (byte)0x23, (byte)0xE9, (byte)0xB8, 
                (byte)0x99, (byte)0xCD, (byte)0xAA, (byte)0xAB, 
                (byte)0xCF, (byte)0x7B, (byte)0xEC, (byte)0x42, 
                (byte)0xCB, (byte)0xA9, (byte)0x0D, (byte)0xE4, 
                (byte)0x74, (byte)0x7E, (byte)0xA2, (byte)0x28, 
                (byte)0xBC, (byte)0x26, (byte)0x70, (byte)0x48, 
                (byte)0x0E, (byte)0xB1, (byte)0x91, (byte)0xE5 
	    }));
	    private static readonly Integer Q3 = new Integer(
            new Math.BigInteger(1, new byte[] { 
                (byte)0x7a, (byte)0x3d, (byte)0x48, (byte)0xc8, 
                (byte)0x0b, (byte)0x17, (byte)0x84, (byte)0x98, 
                (byte)0x53, (byte)0x41, (byte)0x4e, (byte)0xe4, 
                (byte)0x50, (byte)0xcc, (byte)0x63, (byte)0x6c, 
                (byte)0x93, (byte)0xf5, (byte)0x1d, (byte)0x63, 
                (byte)0xf3, (byte)0xc5 
	    })); 
	    private static readonly Integer A3 = new Integer(
            new Math.BigInteger(1, new byte[] {  
                (byte)0x0C, (byte)0xA7, (byte)0xF4, (byte)0x81, 
                (byte)0xB9, (byte)0xD2, (byte)0xAB, (byte)0xE2, 
                (byte)0xE1, (byte)0xCB, (byte)0xC5, (byte)0x8F,
                (byte)0xAB, (byte)0x8B, (byte)0x1F, (byte)0xC9,
                (byte)0xD0, (byte)0x52, (byte)0x34, (byte)0xB0, 
                (byte)0xB7, (byte)0x2A, (byte)0xA6, (byte)0x9B, 
                (byte)0x9A, (byte)0x52, (byte)0x2E, (byte)0x1C, 
                (byte)0x18, (byte)0xEB, (byte)0x73, (byte)0xFC, 
                (byte)0xCF, (byte)0x86, (byte)0xCB, (byte)0xED, 
                (byte)0x32, (byte)0xBD, (byte)0x11, (byte)0xD0, 
                (byte)0x41, (byte)0xAE, (byte)0x04, (byte)0x34, 
                (byte)0x0D, (byte)0x9F, (byte)0x73, (byte)0x2E, 
                (byte)0x7D, (byte)0x6A, (byte)0x88, (byte)0xD0, 
                (byte)0x52, (byte)0xBC, (byte)0x2C, (byte)0xEE, 
                (byte)0x1F, (byte)0x8F, (byte)0x64, (byte)0xCB, 
                (byte)0x08, (byte)0x93, (byte)0xD9, (byte)0x2F, 
                (byte)0x36, (byte)0x5D, (byte)0x16, (byte)0x2E, 
                (byte)0x67, (byte)0xB0, (byte)0x4E, (byte)0xEA, 
                (byte)0xD6, (byte)0xF8, (byte)0xFE, (byte)0x7F, 
                (byte)0x51, (byte)0xB7, (byte)0x4C, (byte)0xF6, 
                (byte)0x1C, (byte)0x90, (byte)0xC9, (byte)0xF4, 
                (byte)0x53, (byte)0xF3, (byte)0x5E, (byte)0x56, 
                (byte)0x8E, (byte)0x22, (byte)0x25, (byte)0xF4, 
                (byte)0x5C, (byte)0x62, (byte)0xBD, (byte)0xF0, 
                (byte)0x1E, (byte)0x96, (byte)0xE1, (byte)0x31, 
                (byte)0x67, (byte)0xCE, (byte)0x33, (byte)0x38, 
                (byte)0x33, (byte)0xB9, (byte)0x3F, (byte)0x65, 
                (byte)0x96, (byte)0x33, (byte)0x20, (byte)0x13, 
                (byte)0x21, (byte)0x12, (byte)0xAA, (byte)0xDB, 
                (byte)0xE4, (byte)0xD9, (byte)0x34, (byte)0x04, 
                (byte)0x7A, (byte)0xFF, (byte)0xBB, (byte)0x35, 
                (byte)0x7D, (byte)0x93, (byte)0x19, (byte)0x83
	    }));
	    private static readonly OctetString H3 = 
            new OctetString(new byte[] {
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00
	    }); 
	    ///////////////////////////////////////////////////////////////////////////
	    // Параметры алгоритма СТБ 1176.2-99 (уровень 6)  
	    ///////////////////////////////////////////////////////////////////////////
        private static readonly Integer L6 = new Integer(1534); 
        private static readonly Integer R6 = new Integer(208 ); 
	    private static readonly Integer P6 = new Integer(
            new Math.BigInteger(1, new byte[] {  
                (byte)0x2E, (byte)0x4B, (byte)0xC3, (byte)0x83, 
                (byte)0x5A, (byte)0x5B, (byte)0x41, (byte)0xE3, 
                (byte)0x5D, (byte)0x9D, (byte)0xC7, (byte)0x35, 
                (byte)0x15, (byte)0x78, (byte)0x91, (byte)0xFC, 
                (byte)0x86, (byte)0x80, (byte)0x64, (byte)0xAD, 
                (byte)0x80, (byte)0x08, (byte)0x68, (byte)0x10, 
                (byte)0xCB, (byte)0x68, (byte)0xF5, (byte)0x80, 
                (byte)0x3D, (byte)0xD7, (byte)0x96, (byte)0x08, 
                (byte)0x20, (byte)0xA2, (byte)0xBA, (byte)0xAF, 
                (byte)0x75, (byte)0x88, (byte)0x96, (byte)0x9A, 
                (byte)0xB9, (byte)0xBF, (byte)0x51, (byte)0x87, 
                (byte)0x3B, (byte)0x1E, (byte)0x39, (byte)0x3D, 
                (byte)0x6D, (byte)0xAB, (byte)0xA0, (byte)0x57, 
                (byte)0xC2, (byte)0x19, (byte)0xED, (byte)0xC6, 
                (byte)0x81, (byte)0x83, (byte)0xB7, (byte)0xEF, 
                (byte)0x07, (byte)0xC4, (byte)0xC3, (byte)0xCE, 
                (byte)0xD5, (byte)0x46, (byte)0x6C, (byte)0x41, 
                (byte)0xA5, (byte)0x98, (byte)0xA2, (byte)0x8B, 
                (byte)0xD0, (byte)0x81, (byte)0x2B, (byte)0xB7, 
                (byte)0xF8, (byte)0xAB, (byte)0x72, (byte)0x1D, 
                (byte)0xCA, (byte)0x6D, (byte)0x6D, (byte)0x09, 
                (byte)0xAF, (byte)0xB9, (byte)0x76, (byte)0x04, 
                (byte)0x4C, (byte)0xE6, (byte)0xD3, (byte)0x6C, 
                (byte)0x5F, (byte)0x4C, (byte)0x1C, (byte)0x58, 
                (byte)0x61, (byte)0x79, (byte)0xEB, (byte)0x2F, 
                (byte)0xB8, (byte)0xF7, (byte)0x74, (byte)0x15, 
                (byte)0x70, (byte)0xE8, (byte)0xB4, (byte)0x92, 
                (byte)0x44, (byte)0xFD, (byte)0x8E, (byte)0x02, 
                (byte)0x43, (byte)0x98, (byte)0xEB, (byte)0xED, 
                (byte)0x9B, (byte)0x3D, (byte)0xD6, (byte)0x6C, 
                (byte)0x59, (byte)0x1F, (byte)0xD8, (byte)0x64, 
                (byte)0x83, (byte)0xB9, (byte)0xFA, (byte)0x62, 
                (byte)0xD6, (byte)0x6F, (byte)0x3A, (byte)0xFF, 
                (byte)0x7F, (byte)0x98, (byte)0xED, (byte)0x22, 
                (byte)0x61, (byte)0xB1, (byte)0x5F, (byte)0x45, 
                (byte)0x5D, (byte)0xEA, (byte)0xB8, (byte)0xD4, 
                (byte)0xDD, (byte)0xC3, (byte)0x85, (byte)0x5D, 
                (byte)0x6E, (byte)0xBA, (byte)0x0C, (byte)0x8A, 
                (byte)0x70, (byte)0x6F, (byte)0x48, (byte)0xAC, 
                (byte)0xA2, (byte)0x09, (byte)0xAC, (byte)0xE2, 
                (byte)0x87, (byte)0xAF, (byte)0x3A, (byte)0x81, 
                (byte)0xCD, (byte)0x0A, (byte)0xF7, (byte)0x11, 
                (byte)0xF8, (byte)0x2A, (byte)0x1C, (byte)0x65, 
                (byte)0x3C, (byte)0x5E, (byte)0x5A, (byte)0xAA, 
                (byte)0x6B, (byte)0xC0, (byte)0x5A, (byte)0xA9, 
                (byte)0x25, (byte)0x91, (byte)0xAC, (byte)0x22, 
                (byte)0x5B, (byte)0xEB, (byte)0xC6, (byte)0xE5, 
                (byte)0x5E, (byte)0x95, (byte)0x34, (byte)0x53
	    }));
	    private static readonly Integer Q6 = new Integer(
            new Math.BigInteger(1, new byte[] { 
                (byte)0xB7, (byte)0xB5, (byte)0x41, (byte)0x7D, 
                (byte)0x80, (byte)0x85,	(byte)0x27, (byte)0xDE, 
                (byte)0xD8, (byte)0xEA, (byte)0xEC, (byte)0x7C, 
                (byte)0xFC, (byte)0xB9, (byte)0x74, (byte)0x2C, 
                (byte)0x87, (byte)0x1B, (byte)0xDF, (byte)0x45, 
                (byte)0xDA, (byte)0x71, (byte)0x5F, (byte)0x6A, 
                (byte)0x45, (byte)0x3D 
	    })); 
	    private static readonly Integer A6 = new Integer(
            new Math.BigInteger(1, new byte[] {  
                (byte)0x01, (byte)0x7C, (byte)0xA5, (byte)0x4B, 
                (byte)0xC1, (byte)0xBD, (byte)0x33, (byte)0x8D, 
                (byte)0x2F, (byte)0x76, (byte)0x0A, (byte)0xCF, 
                (byte)0x08, (byte)0xD1, (byte)0x12, (byte)0x4A, 
                (byte)0x57, (byte)0xFF, (byte)0x86, (byte)0x6C, 
                (byte)0x24, (byte)0xF3, (byte)0xDC, (byte)0x85, 
                (byte)0x19, (byte)0xE0, (byte)0x3C, (byte)0x44, 
                (byte)0x21, (byte)0x0F, (byte)0x4E, (byte)0x08, 
                (byte)0xD9, (byte)0x95, (byte)0x02, (byte)0x80, 
                (byte)0xC0, (byte)0xCC, (byte)0x9F, (byte)0xBD, 
                (byte)0xBA, (byte)0x39, (byte)0x16, (byte)0xD4, 
                (byte)0x18, (byte)0xCF, (byte)0x19, (byte)0x99, 
                (byte)0xB9, (byte)0x1E, (byte)0x41, (byte)0x3C, 
                (byte)0x40, (byte)0x2B, (byte)0xC0, (byte)0x0D, 
                (byte)0xB8, (byte)0xB6, (byte)0xBA, (byte)0x76, 
                (byte)0x8C, (byte)0x45, (byte)0x25, (byte)0x7F, 
                (byte)0x25, (byte)0xE9, (byte)0xF4, (byte)0xD7, 
                (byte)0x1C, (byte)0xC7, (byte)0x8E, (byte)0xD3, 
                (byte)0xEF, (byte)0x12, (byte)0x01, (byte)0xD0, 
                (byte)0x12, (byte)0xE6, (byte)0xB9, (byte)0xCE, 
                (byte)0x24, (byte)0x91, (byte)0x3F, (byte)0x2F, 
                (byte)0x57, (byte)0xE3, (byte)0x86, (byte)0x06, 
                (byte)0xC8, (byte)0x4D, (byte)0x8E, (byte)0x18, 
                (byte)0x1A, (byte)0x42, (byte)0x0D, (byte)0x54, 
                (byte)0xF1, (byte)0xB1, (byte)0xE2, (byte)0xA1, 
                (byte)0x98, (byte)0x7B, (byte)0xED, (byte)0x42, 
                (byte)0x20, (byte)0x79, (byte)0xE4, (byte)0x8E, 
                (byte)0x88, (byte)0xA0, (byte)0x3E, (byte)0x73, 
                (byte)0x0C, (byte)0x36, (byte)0x05, (byte)0x5B, 
                (byte)0x9C, (byte)0x9A, (byte)0x15, (byte)0xD4, 
                (byte)0x2B, (byte)0xA8, (byte)0xDC, (byte)0xCB, 
                (byte)0xF8, (byte)0x10, (byte)0xE1, (byte)0x93, 
                (byte)0xA7, (byte)0x65, (byte)0x3A, (byte)0x9C, 
                (byte)0x17, (byte)0x5A, (byte)0x81, (byte)0x85, 
                (byte)0xFD, (byte)0x73, (byte)0xBB, (byte)0x1C, 
                (byte)0x17, (byte)0x13, (byte)0x9B, (byte)0x31, 
                (byte)0x16, (byte)0x0B, (byte)0x42, (byte)0xCA, 
                (byte)0xED, (byte)0xF0, (byte)0x1F, (byte)0x01, 
                (byte)0xF7, (byte)0x99, (byte)0xA0, (byte)0xB6, 
                (byte)0x1A, (byte)0xF8, (byte)0xFF, (byte)0x8B, 
                (byte)0xDE, (byte)0x3E, (byte)0x2A, (byte)0xC1, 
                (byte)0x71, (byte)0x45, (byte)0xA7, (byte)0x27, 
                (byte)0xFD, (byte)0x7A, (byte)0xE0, (byte)0x27, 
                (byte)0x1B, (byte)0xF9, (byte)0x70, (byte)0x92, 
                (byte)0xBF, (byte)0x73, (byte)0x0F, (byte)0x08, 
                (byte)0x16, (byte)0xC8, (byte)0xF3, (byte)0x76, 
                (byte)0x45, (byte)0x0A, (byte)0x35, (byte)0x0E, 
                (byte)0xB7, (byte)0xC7, (byte)0x80, (byte)0x44
	    }));
	    private static readonly OctetString H6 = 
            new OctetString(new byte[] {
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00
	    }); 
	    ///////////////////////////////////////////////////////////////////////////
	    // Параметры алгоритма СТБ 1176.2-99 (уровень 10)  
	    ///////////////////////////////////////////////////////////////////////////
        private static readonly Integer L10 = new Integer(2462); 
        private static readonly Integer R10 = new Integer(257 ); 
	    private static readonly Integer P10 = new Integer(
            new Math.BigInteger(1, new byte[] {  
                (byte)0x2F, (byte)0x01, (byte)0xEA, (byte)0xCA,
                (byte)0x03, (byte)0x63, (byte)0xBB, (byte)0x43, 
                (byte)0xDA, (byte)0x7C, (byte)0xF0, (byte)0xA2, 
                (byte)0x14, (byte)0xD2, (byte)0xFC, (byte)0x03, 
                (byte)0x3A, (byte)0x59, (byte)0x2B, (byte)0x2F, 
                (byte)0x2E, (byte)0x3F, (byte)0xB5, (byte)0x8D, 
                (byte)0x61, (byte)0xD7, (byte)0xE4, (byte)0x2B, 
                (byte)0xAA, (byte)0x17, (byte)0x45, (byte)0x5B, 
                (byte)0x38, (byte)0x16, (byte)0x76, (byte)0x84, 
                (byte)0xBF, (byte)0x8F, (byte)0x41, (byte)0x8E, 
                (byte)0x2D, (byte)0xF4, (byte)0xEF, (byte)0xD3, 
                (byte)0xE1, (byte)0xD1, (byte)0x05, (byte)0xE0, 
                (byte)0x34, (byte)0xA4, (byte)0x97, (byte)0xCF, 
                (byte)0xC0, (byte)0xFA, (byte)0x4C, (byte)0x02, 
                (byte)0x39, (byte)0xE7, (byte)0x55, (byte)0xC1, 
                (byte)0x39, (byte)0x65, (byte)0xD0, (byte)0x96, 
                (byte)0x45, (byte)0x2B, (byte)0x05, (byte)0x5A, 
                (byte)0x53, (byte)0x14, (byte)0xC8, (byte)0x0F, 
                (byte)0xC7, (byte)0xF6, (byte)0x3C, (byte)0x81, 
                (byte)0x01, (byte)0x4E, (byte)0xEE, (byte)0x3F, 
                (byte)0xA9, (byte)0xC6, (byte)0xFD, (byte)0xFE, 
                (byte)0x9A, (byte)0x88, (byte)0xA2, (byte)0xE8, 
                (byte)0xD1, (byte)0x13, (byte)0x7A, (byte)0xBE, 
                (byte)0x01, (byte)0xE6, (byte)0xDD, (byte)0x80, 
                (byte)0x6D, (byte)0x0A, (byte)0x64, (byte)0xA4, 
                (byte)0x05, (byte)0xB3, (byte)0xF3, (byte)0x0D, 
                (byte)0x90, (byte)0x9C, (byte)0x84, (byte)0xB6, 
                (byte)0x00, (byte)0x8F, (byte)0x9D, (byte)0x06, 
                (byte)0xD1, (byte)0x10, (byte)0x20, (byte)0x24, 
                (byte)0xA7, (byte)0xD2, (byte)0xCF, (byte)0x7F, 
                (byte)0x5C, (byte)0x04, (byte)0x18, (byte)0x87, 
                (byte)0x3B, (byte)0xD2, (byte)0x22, (byte)0xEF, 
                (byte)0x2B, (byte)0xE1, (byte)0xBF, (byte)0xAF, 
                (byte)0x66, (byte)0xCB, (byte)0x3B, (byte)0xBD, 
                (byte)0x7E, (byte)0x34, (byte)0xAE, (byte)0xDF, 
                (byte)0x10, (byte)0xC5, (byte)0xA7, (byte)0x0E, 
                (byte)0x1C, (byte)0xAC, (byte)0x05, (byte)0x66, 
                (byte)0xDB, (byte)0xC9, (byte)0x6E, (byte)0x05, 
                (byte)0x8B, (byte)0x5D, (byte)0x0B, (byte)0x9D, 
                (byte)0x68, (byte)0x75, (byte)0x95, (byte)0x1B, 
                (byte)0x0A, (byte)0xDF, (byte)0x8D, (byte)0x09, 
                (byte)0xBC, (byte)0xE5, (byte)0xCE, (byte)0x60, 
                (byte)0xFC, (byte)0x1C, (byte)0xBE, (byte)0xC0, 
                (byte)0xC4, (byte)0x9D, (byte)0xE8, (byte)0xA4, 
                (byte)0x94, (byte)0x56, (byte)0x82, (byte)0x63, 
                (byte)0x9E, (byte)0x9C, (byte)0xF5, (byte)0x49, 
                (byte)0x93, (byte)0xA6, (byte)0x22, (byte)0x51, 
                (byte)0x37, (byte)0x2D, (byte)0xD0, (byte)0xEE, 
                (byte)0xB3, (byte)0x00, (byte)0x76, (byte)0x44, 
                (byte)0x5E, (byte)0xFD, (byte)0x9B, (byte)0x15, 
                (byte)0x51, (byte)0x94, (byte)0xFA, (byte)0x32, 
                (byte)0x54, (byte)0xCF, (byte)0x3D, (byte)0xA6, 
                (byte)0xD0, (byte)0xEE, (byte)0x8B, (byte)0x0C, 
                (byte)0x0F, (byte)0x51, (byte)0x5D, (byte)0xF1, 
                (byte)0x94, (byte)0x9E, (byte)0x8F, (byte)0x8B, 
                (byte)0x67, (byte)0xE7, (byte)0xDC, (byte)0x1A, 
                (byte)0x14, (byte)0x43, (byte)0x30, (byte)0x33, 
                (byte)0x9B, (byte)0xA0, (byte)0xAE, (byte)0xA1, 
                (byte)0xE9, (byte)0x3C, (byte)0x55, (byte)0x1A, 
                (byte)0x31, (byte)0x17, (byte)0xCE, (byte)0x98, 
                (byte)0xAF, (byte)0xD6, (byte)0x94, (byte)0x73, 
                (byte)0x26, (byte)0x67, (byte)0xE4, (byte)0xCE, 
                (byte)0x22, (byte)0x67, (byte)0x79, (byte)0xE3, 
                (byte)0x47, (byte)0x26, (byte)0xE7, (byte)0x8E, 
                (byte)0x13, (byte)0xE9, (byte)0x16, (byte)0xD8, 
                (byte)0x91, (byte)0x6D, (byte)0x29, (byte)0x18, 
                (byte)0xBD, (byte)0xF5, (byte)0xDD, (byte)0x77, 
                (byte)0x8C, (byte)0x99, (byte)0x38, (byte)0xE2, 
                (byte)0xF5, (byte)0x2E, (byte)0x34, (byte)0x25, 
                (byte)0x71, (byte)0x4C, (byte)0xA7, (byte)0xC9, 
                (byte)0x12, (byte)0x23, (byte)0x30, (byte)0xD9, 
                (byte)0x2A, (byte)0x2D, (byte)0xF0, (byte)0x86, 
                (byte)0x15, (byte)0x16, (byte)0xCC, (byte)0xE3, 
                (byte)0x51, (byte)0xE6, (byte)0xD7, (byte)0x6D, 
                (byte)0x75, (byte)0x37, (byte)0x43, (byte)0x2A, 
                (byte)0xF1, (byte)0xF2, (byte)0x28, (byte)0x5F, 
                (byte)0x6F, (byte)0x9B, (byte)0x1D, (byte)0x95
	    }));
	    private static readonly Integer Q10 = new Integer(
            new Math.BigInteger(1, new byte[] { 
                (byte)0x01, (byte)0xC3, (byte)0xCE, (byte)0xD5, 
                (byte)0x46,	(byte)0x6C, (byte)0x41, (byte)0xA5, 
                (byte)0x82,	(byte)0x9D, (byte)0x09, (byte)0x9F, 
                (byte)0xA4,	(byte)0x44, (byte)0x91, (byte)0xB1, 
                (byte)0x19,	(byte)0x3D, (byte)0x1A, (byte)0xB1, 
                (byte)0x38,	(byte)0xA1, (byte)0x78, (byte)0x10, 
                (byte)0x46,	(byte)0x73, (byte)0xD1, (byte)0x52, 
                (byte)0xC1, (byte)0x4F, (byte)0x80, (byte)0x4E, 
                (byte)0xEB
	    })); 
	    private static readonly Integer A10 = new Integer(
            new Math.BigInteger(1, new byte[] {  
                (byte)0x1E, (byte)0x92, (byte)0x18, (byte)0x04, 
                (byte)0xB4, (byte)0xE9, (byte)0x62, (byte)0x4E, 
                (byte)0x38, (byte)0xCE, (byte)0x41, (byte)0xC7, 
                (byte)0x79, (byte)0x84, (byte)0x6D, (byte)0x4D, 
                (byte)0xBB, (byte)0x98, (byte)0xD5, (byte)0x3D, 
                (byte)0xF6, (byte)0x34, (byte)0xED, (byte)0x69, 
                (byte)0x85, (byte)0xFA, (byte)0x42, (byte)0xBF, 
                (byte)0x07, (byte)0x9A, (byte)0x7B, (byte)0xD0, 
                (byte)0x5A, (byte)0xAC, (byte)0x50, (byte)0x8F, 
                (byte)0xBF, (byte)0xC4, (byte)0x78, (byte)0x92, 
                (byte)0x8F, (byte)0x9E, (byte)0xE2, (byte)0xB2, 
                (byte)0x2C, (byte)0x2F, (byte)0x1B, (byte)0x97, 
                (byte)0xD9, (byte)0x8F, (byte)0x61, (byte)0x47, 
                (byte)0x7E, (byte)0xDC, (byte)0x2A, (byte)0xAB, 
                (byte)0x4A, (byte)0xA3, (byte)0x24, (byte)0x99, 
                (byte)0x55, (byte)0x2F, (byte)0xF7, (byte)0x2F, 
                (byte)0xF1, (byte)0xB3, (byte)0xAE, (byte)0xF2, 
                (byte)0x7F, (byte)0x52, (byte)0x31, (byte)0xDA, 
                (byte)0x18, (byte)0x80, (byte)0xA1, (byte)0x53, 
                (byte)0xF1, (byte)0xB2, (byte)0x83, (byte)0xE2, 
                (byte)0x2A, (byte)0x38, (byte)0x65, (byte)0x54, 
                (byte)0x3B, (byte)0x64, (byte)0x2C, (byte)0x35, 
                (byte)0xEF, (byte)0xE2, (byte)0x11, (byte)0xC5, 
                (byte)0x04, (byte)0x6A, (byte)0xAE, (byte)0x39, 
                (byte)0x6C, (byte)0x28, (byte)0x11, (byte)0xB8, 
                (byte)0x1D, (byte)0xBE, (byte)0xD9, (byte)0xC4, 
                (byte)0xAF, (byte)0xB1, (byte)0xF3, (byte)0x9E, 
                (byte)0xD2, (byte)0xF3, (byte)0x67, (byte)0x99, 
                (byte)0x1C, (byte)0xC7, (byte)0x79, (byte)0x80, 
                (byte)0x51, (byte)0xB9, (byte)0x9F, (byte)0x0B, 
                (byte)0x7F, (byte)0xEE, (byte)0x1A, (byte)0xB4, 
                (byte)0xE8, (byte)0x5C, (byte)0xDB, (byte)0xBD, 
                (byte)0x85, (byte)0x3B, (byte)0xCB, (byte)0x1B, 
                (byte)0xA1, (byte)0x90, (byte)0x21, (byte)0x75, 
                (byte)0x9E, (byte)0x58, (byte)0x8C, (byte)0xC7, 
                (byte)0x0A, (byte)0xF9, (byte)0x88, (byte)0x8A, 
                (byte)0x5C, (byte)0x4E, (byte)0xC7, (byte)0xFF, 
                (byte)0xF3, (byte)0x30, (byte)0x74, (byte)0x9C, 
                (byte)0xEA, (byte)0x18, (byte)0x90, (byte)0xBC, 
                (byte)0xF7, (byte)0x22, (byte)0xBA, (byte)0xE9, 
                (byte)0x37, (byte)0xD2, (byte)0xB3, (byte)0x66, 
                (byte)0x38, (byte)0x05, (byte)0xDC, (byte)0x67, 
                (byte)0xF5, (byte)0x5A, (byte)0x59, (byte)0x1B, 
                (byte)0x6E, (byte)0x28, (byte)0x89, (byte)0x62, 
                (byte)0x9D, (byte)0x11, (byte)0xCD, (byte)0x03, 
                (byte)0xC1, (byte)0x55, (byte)0x5A, (byte)0xC8, 
                (byte)0x63, (byte)0x82, (byte)0x7B, (byte)0x88, 
                (byte)0xA0, (byte)0x45, (byte)0x1A, (byte)0x47, 
                (byte)0x26, (byte)0x59, (byte)0x73, (byte)0x59, 
                (byte)0xE5, (byte)0x90, (byte)0x2C, (byte)0xAD, 
                (byte)0x1E, (byte)0xEA, (byte)0xF7, (byte)0x94, 
                (byte)0xEB, (byte)0x60, (byte)0x05, (byte)0x30, 
                (byte)0x99, (byte)0x88, (byte)0xF3, (byte)0x33, 
                (byte)0x95, (byte)0xF4, (byte)0x20, (byte)0x41, 
                (byte)0x4B, (byte)0xB0, (byte)0xB2, (byte)0x18, 
                (byte)0x75, (byte)0x30, (byte)0x5E, (byte)0x12, 
                (byte)0xCC, (byte)0xF1, (byte)0x77, (byte)0xBE, 
                (byte)0x76, (byte)0x5D, (byte)0xF1, (byte)0x8E, 
                (byte)0xDD, (byte)0xB7, (byte)0xE9, (byte)0xAA, 
                (byte)0x37, (byte)0x63, (byte)0x18, (byte)0x67, 
                (byte)0x94, (byte)0xD3, (byte)0xC4, (byte)0x46, 
                (byte)0x38, (byte)0xE1, (byte)0xB1, (byte)0x1A, 
                (byte)0xB8, (byte)0x7C, (byte)0x69, (byte)0x57, 
                (byte)0xF5, (byte)0xC1, (byte)0x47, (byte)0x87, 
                (byte)0xD5, (byte)0x40, (byte)0x95, (byte)0x9D, 
                (byte)0x3A, (byte)0xCB, (byte)0x53, (byte)0xD3, 
                (byte)0x1B, (byte)0xBB, (byte)0x24, (byte)0x82, 
                (byte)0x3F, (byte)0x5A, (byte)0xC5, (byte)0x05, 
                (byte)0xFA, (byte)0xF5, (byte)0xD8, (byte)0x6E, 
                (byte)0x0E, (byte)0xBA, (byte)0x65, (byte)0xAE, 
                (byte)0xCB, (byte)0x14, (byte)0xB4, (byte)0xB0, 
                (byte)0x06, (byte)0x01, (byte)0xCC, (byte)0x24, 
                (byte)0x26, (byte)0xCC, (byte)0x47, (byte)0x6D, 
                (byte)0x88, (byte)0x37, (byte)0xCC, (byte)0x6C, 
                (byte)0x4F, (byte)0xCE, (byte)0x7B, (byte)0x07, 
                (byte)0x0E, (byte)0x19, (byte)0xAB, (byte)0xEB, 
                (byte)0x6D, (byte)0xC3, (byte)0x4F, (byte)0xEE
	    })); 
	    private static readonly OctetString H10 =  
            new OctetString(new byte[] {
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00
	    }); 
	    ///////////////////////////////////////////////////////////////////////////
	    // Таблица именованных параметров
	    ///////////////////////////////////////////////////////////////////////////
	    private static readonly Dictionary<String, BDSParamsList> set = 
            new Dictionary<String, BDSParamsList>(); 
	    static BDSParamsList()
        {
		    set.Add(OID.stb11762_params3_bds , new BDSParamsList(L3,  R3,  P3,  Q3,  A3,  H3,  null)); 
		    set.Add(OID.stb11762_params6_bds , new BDSParamsList(L6,  R6,  P6,  Q6,  A6,  H6,  null)); 
		    set.Add(OID.stb11762_params10_bds, new BDSParamsList(L10, R10, P10, Q10, A10, H10, null)); 
	    }
	    // получить именованные параметры
	    public static BDSParamsList Parameters(string oid) { return set[oid]; } 
    }
}
