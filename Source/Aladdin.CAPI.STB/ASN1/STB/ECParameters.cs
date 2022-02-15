using System; 
using System.IO; 
using System.Collections.Generic;

namespace Aladdin.ASN1.STB
{
    ////////////////////////////////////////////////////////////////////////////////
    // ECParameters ::= SEQUENCE {
    //      version INTEGER {ecpVer1(1)} (ecpVer1),
    //      fieldID FieldID,
    //      curve Curve,
    //      base OCTET STRING (SIZE(32|48|64)),
    //      order INTEGER,
    //      cofactor INTEGER (1) OPTIONAL
    // }
    ////////////////////////////////////////////////////////////////////////////////
    public class ECParameters : Sequence
    {
	    // информация о структуре
	    private static readonly ObjectInfo[] info = new ObjectInfo[] { 
        
		    new ObjectInfo(new ObjectCreator<Integer    >().Factory(      ), Cast.N, Tag.Any                  ), 
		    new ObjectInfo(new ObjectCreator<FieldID    >().Factory(      ), Cast.N, Tag.Any                  ), 
		    new ObjectInfo(new ObjectCreator<Curve      >().Factory(      ), Cast.N, Tag.Any                  ), 
		    new ObjectInfo(new ObjectCreator<OctetString>().Factory(32, 64), Cast.N, Tag.Any                  ), 
		    new ObjectInfo(new ObjectCreator<Integer    >().Factory(      ), Cast.N, Tag.Any                  ), 
		    new ObjectInfo(new ObjectCreator<Integer    >().Factory(      ), Cast.O, Tag.Any, new Integer(1)  ) 
	    }; 
	    // конструктор при раскодировании
	    public ECParameters(IEncodable encodable) : base(encodable, info)
        { 
            // определить размер параметра
            int lengthBase = Base.Value.Length; 
    
            // проверить корректность параметра
            if (lengthBase != 32 && lengthBase != 48 && lengthBase != 64) throw new InvalidDataException(); 
        }  
	    // конструктор при закодировании
	    public ECParameters(Integer version, FieldID fieldID, 
            Curve curve, OctetString generator, Integer order, Integer cofactor)
		    : base(info, version, fieldID, curve, generator, order, cofactor)  
        {
            // определить размер параметра
            int lengthBase = Base.Value.Length; 
    
            // проверить корректность параметра
            if (lengthBase != 32 && lengthBase != 48 && lengthBase != 64) throw new ArgumentException(); 
        }
	    public Integer     Version  { get { return (Integer    )this[0]; }} 
	    public FieldID     FieldID  { get { return (FieldID    )this[1]; }} 
	    public Curve       Curve    { get { return (Curve      )this[2]; }} 
	    public OctetString Base     { get { return (OctetString)this[3]; }} 
	    public Integer     Order    { get { return (Integer    )this[4]; }} 
	    public Integer     Cofactor { get { return (Integer    )this[5]; }} 
    
	    ///////////////////////////////////////////////////////////////////////////
	    // Параметры алгоритма СТБ.34.101.45-2013 (длина ключа 128)
	    ///////////////////////////////////////////////////////////////////////////
	    private static readonly byte[] P3 = {
		    (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
		    (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
		    (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
		    (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
		    (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
		    (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
		    (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
		    (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0x43			
	    }; 
	    private static readonly byte[] A3 = {
		    (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF,
		    (byte)0xFF, (byte)0xFF, (byte)0xFF,	(byte)0xFF,  
		    (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
		    (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
		    (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
		    (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
		    (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
		    (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0x40
	    }; 
	    private static readonly byte[] B3 = {
		    (byte)0x77, (byte)0xCE, (byte)0x6C, (byte)0x15,
		    (byte)0x15, (byte)0xF3, (byte)0xA8, (byte)0xED,
		    (byte)0xD2, (byte)0xC1, (byte)0x3A, (byte)0xAB,
		    (byte)0xE4, (byte)0xD8, (byte)0xFB, (byte)0xBE,
		    (byte)0x4C, (byte)0xF5, (byte)0x50, (byte)0x69,
		    (byte)0x97, (byte)0x8B, (byte)0x92, (byte)0x53,
		    (byte)0xB2, (byte)0x2E, (byte)0x7D, (byte)0x6B,
		    (byte)0xD6, (byte)0x9C, (byte)0x03, (byte)0xF1
	    }; 
        private static readonly byte[] SEED3 = {
            (byte)0x5E, (byte)0x38, (byte)0x01, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00
        }; 
	    private static readonly byte[] Q3 = {
		    (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF,
		    (byte)0xFF, (byte)0xFF, (byte)0xFF,	(byte)0xFF,  
		    (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
		    (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
		    (byte)0xD9, (byte)0x5C, (byte)0x8E, (byte)0xD6,
		    (byte)0x0D, (byte)0xFB, (byte)0x4D, (byte)0xFC,
		    (byte)0x7E, (byte)0x5A, (byte)0xBF, (byte)0x99,
		    (byte)0x26, (byte)0x3D, (byte)0x66, (byte)0x07
	    };
	    private static readonly byte[] GY3 = {
		    (byte)0x6B, (byte)0xF7, (byte)0xFC, (byte)0x3C,
		    (byte)0xFB, (byte)0x16, (byte)0xD6, (byte)0x9F,
		    (byte)0x5C, (byte)0xE4, (byte)0xC9, (byte)0xA3,
		    (byte)0x51, (byte)0xD6, (byte)0x83, (byte)0x5D,
		    (byte)0x78, (byte)0x91, (byte)0x39, (byte)0x66,
		    (byte)0xC4, (byte)0x08, (byte)0xF6, (byte)0x52,
		    (byte)0x1E, (byte)0x29, (byte)0xCF, (byte)0x18,
		    (byte)0x04, (byte)0x51, (byte)0x6A, (byte)0x93
	    }; 
	    ///////////////////////////////////////////////////////////////////////////
	    // Параметры алгоритма СТБ.34.101.45-2013 (длина ключа 192)
	    ///////////////////////////////////////////////////////////////////////////
	    private static readonly byte[] P6 = {
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
		    (byte)0xFF, (byte)0xFF, (byte)0xFE, (byte)0xC3 
	    }; 
	    private static readonly byte[] A6 = {
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
		    (byte)0xFF, (byte)0xFF, (byte)0xFE, (byte)0xC0 
	    }; 
	    private static readonly byte[] B6 = {
		    (byte)0x3C, (byte)0x75, (byte)0xDF, (byte)0xE1,			
		    (byte)0x95, (byte)0x9C, (byte)0xEF, (byte)0x20, 
		    (byte)0x33, (byte)0x07, (byte)0x5A, (byte)0xAB, 
		    (byte)0x65, (byte)0x5D, (byte)0x34, (byte)0xD2, 
		    (byte)0x71, (byte)0x27, (byte)0x48, (byte)0xBB,
		    (byte)0x0F, (byte)0xFB, (byte)0xB1, (byte)0x96,
		    (byte)0xA6, (byte)0x21, (byte)0x6A, (byte)0xF9, 
		    (byte)0xE9, (byte)0x71, (byte)0x2E, (byte)0x3A,
		    (byte)0x14, (byte)0xBD, (byte)0xE2, (byte)0xF0, 
		    (byte)0xF3, (byte)0xCE, (byte)0xBD, (byte)0x7C, 
		    (byte)0xBC, (byte)0xA7, (byte)0xFC, (byte)0x23, 
		    (byte)0x68, (byte)0x73, (byte)0xBF, (byte)0x64 
	    }; 
        private static readonly byte[] SEED6 = {
            (byte)0x23, (byte)0xAF, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00
        }; 
	    private static readonly byte[] Q6 = {
		    (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF,
		    (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
		    (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
		    (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
		    (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF,
		    (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFE, 
		    (byte)0x6C, (byte)0xCC, (byte)0xC4, (byte)0x03, 
		    (byte)0x73, (byte)0xAF, (byte)0x7B, (byte)0xBB, 
		    (byte)0x80, (byte)0x46, (byte)0xDA, (byte)0xE7, 
		    (byte)0xA6, (byte)0xA4, (byte)0xFF, (byte)0x0A, 
		    (byte)0x3D, (byte)0xB7, (byte)0xDC, (byte)0x3F, 
		    (byte)0xF3, (byte)0x0C, (byte)0xA7, (byte)0xB7 
	    }; 
	    private static readonly byte[] GY6 = {
		    (byte)0x5D, (byte)0x43, (byte)0x82, (byte)0x24,
		    (byte)0xA8, (byte)0x2E, (byte)0x9E, (byte)0x9E, 
		    (byte)0x63, (byte)0x30, (byte)0x11, (byte)0x7E, 
		    (byte)0x43, (byte)0x2D, (byte)0xBF, (byte)0x89, 
		    (byte)0x3A, (byte)0x72, (byte)0x9A, (byte)0x11,
		    (byte)0xDC, (byte)0x86, (byte)0xFF, (byte)0xA0, 
		    (byte)0x05, (byte)0x49, (byte)0xE7, (byte)0x9E, 
		    (byte)0x66, (byte)0xB1, (byte)0xD3, (byte)0x55, 
		    (byte)0x84, (byte)0x40, (byte)0x3E, (byte)0x27, 
		    (byte)0x6B, (byte)0x2A, (byte)0x42, (byte)0xF9, 
		    (byte)0xEA, (byte)0x5E, (byte)0xCB, (byte)0x31, 
		    (byte)0xF7, (byte)0x33, (byte)0xC4, (byte)0x51 
	    }; 
	    ///////////////////////////////////////////////////////////////////////////
	    // Параметры алгоритма СТБ.34.101.45-2013 (длина ключа 192)
	    ///////////////////////////////////////////////////////////////////////////
	    private static readonly byte[] P10 = {
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
	    }; 
	    private static readonly byte[] A10 = {
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
	    }; 
	    private static readonly byte[] B10 = {
		    (byte)0x6C, (byte)0xB4, (byte)0x59, (byte)0x44,
		    (byte)0x93, (byte)0x3B, (byte)0x8C, (byte)0x43, 
		    (byte)0xD8, (byte)0x8C, (byte)0x5D, (byte)0x6A, 
		    (byte)0x60, (byte)0xFD, (byte)0x58, (byte)0x89, 
		    (byte)0x5B, (byte)0xC6, (byte)0xA9, (byte)0xEE, 
		    (byte)0xDD, (byte)0x5D, (byte)0x25, (byte)0x51, 
		    (byte)0x17, (byte)0xCE, (byte)0x13, (byte)0xE3, 
		    (byte)0xDA, (byte)0xAD, (byte)0xB0, (byte)0x88, 
		    (byte)0x27, (byte)0x11, (byte)0xDC, (byte)0xB5,
		    (byte)0xC4, (byte)0x24, (byte)0x5E, (byte)0x95, 
		    (byte)0x29, (byte)0x33, (byte)0x00, (byte)0x8C, 
		    (byte)0x87, (byte)0xAC, (byte)0xA2, (byte)0x43, 
		    (byte)0xEA, (byte)0x86, (byte)0x22, (byte)0x27, 
		    (byte)0x3A, (byte)0x49, (byte)0xA2, (byte)0x7A, 
		    (byte)0x09, (byte)0x34, (byte)0x69, (byte)0x98, 
		    (byte)0xD6, (byte)0x13, (byte)0x9C, (byte)0x90 
	    }; 
        private static readonly byte[] SEED10 = {
            (byte)0xAE, (byte)0x17, (byte)0x02, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00    
        }; 
	    private static readonly byte[] Q10 = {
		    (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF,
		    (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
		    (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
		    (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
		    (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
		    (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
		    (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
		    (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF,
		    (byte)0xB2, (byte)0xC0, (byte)0x09, (byte)0x2C,
		    (byte)0x01, (byte)0x98, (byte)0x00, (byte)0x4E, 
		    (byte)0xF2, (byte)0x6B, (byte)0xEB, (byte)0xB0, 
		    (byte)0x2E, (byte)0x21, (byte)0x13, (byte)0xF4, 
		    (byte)0x36, (byte)0x1B, (byte)0xCA, (byte)0xE5, 
		    (byte)0x95, (byte)0x56, (byte)0xDF, (byte)0x32, 
		    (byte)0xDC, (byte)0xFF, (byte)0xAD, (byte)0x49, 
		    (byte)0x0D, (byte)0x06, (byte)0x8E, (byte)0xF1 
	    }; 
	    private static readonly byte[] GY10 = {
		    (byte)0xA8, (byte)0x26, (byte)0xFF, (byte)0x7A,
		    (byte)0xE4, (byte)0x03, (byte)0x76, (byte)0x81, 
		    (byte)0xB1, (byte)0x82, (byte)0xE6, (byte)0xF7, 
		    (byte)0xA0, (byte)0xD1, (byte)0x8F, (byte)0xAB, 
		    (byte)0xB0, (byte)0xAB, (byte)0x41, (byte)0xB3, 
		    (byte)0xB3, (byte)0x61, (byte)0xBC, (byte)0xE2, 
		    (byte)0xD2, (byte)0xED, (byte)0xF8, (byte)0x1B, 
		    (byte)0x00, (byte)0xCC, (byte)0xCA, (byte)0xDA, 
		    (byte)0x69, (byte)0x73, (byte)0xDD, (byte)0xE2,
		    (byte)0x0E, (byte)0xFA, (byte)0x6F, (byte)0xD2, 
		    (byte)0xFF, (byte)0x77, (byte)0x73, (byte)0x95, 
		    (byte)0xEE, (byte)0xE8, (byte)0x22, (byte)0x61, 
		    (byte)0x67, (byte)0xAA, (byte)0x83, (byte)0xB9, 
		    (byte)0xC9, (byte)0x4C, (byte)0x0D, (byte)0x04, 
		    (byte)0xB7, (byte)0x92, (byte)0xAE, (byte)0x6F, 
		    (byte)0xCE, (byte)0xEF, (byte)0xED, (byte)0xBD 
	    };
	    ///////////////////////////////////////////////////////////////////////////
        // Закодировать именованные параметры
	    ///////////////////////////////////////////////////////////////////////////
        private static ECParameters Encode(int l, 
            byte[] p, byte[] a, byte[] b, byte[] seed, byte[] q, byte[] gy)
        {
            // указать способ кодирования чисел
            Math.Endian endian = Math.Endian.BigEndian; 
        
            // указать идентификатор типа поля
            ObjectIdentifier fieldType = new ObjectIdentifier(OID.stb34101_bign_primeField); 
        
            // закодировать параметры поля
            FieldID fieldID = new FieldID(fieldType, 
                new Integer(Math.Convert.ToBigInteger(p, endian))
            ); 
            // закодировать параметры a и b кривой
            a  = (byte[])a .Clone(); Arrays.Reverse(a );
            b  = (byte[])b .Clone(); Arrays.Reverse(b );
            gy = (byte[])gy.Clone(); Arrays.Reverse(gy);
            
            // выполнить выравнивание данных
            OctetString A  = new OctetString(Arrays.CopyOf(a , l / 4)); 
            OctetString B  = new OctetString(Arrays.CopyOf(b , l / 4));
            OctetString GY = new OctetString(Arrays.CopyOf(gy, l / 4));
            
            // закодировать параметры эллиптичесой кривой
            Curve curve = new Curve(A, B, new BitString(seed)); 
            
            // закодировать параметры в целом
            return new ECParameters(new Integer(1), fieldID, curve, 
                GY, new Integer(Math.Convert.ToBigInteger(q, endian)), null
            ); 
        }
	    // таблица именованных параметров
	    private static readonly Dictionary<String, ECParameters> set = 
		    new Dictionary<String, ECParameters>(); 
	    static ECParameters()
        {
		    set.Add(OID.stb34101_bign_curve256_v1, Encode(
                128, P3, A3, B3, SEED3, Q3, GY3
		    )); 
		    set.Add(OID.stb34101_bign_curve384_v1, Encode(
                192, P6, A6, B6, SEED6, Q6, GY6
		    )); 
		    set.Add(OID.stb34101_bign_curve512_v1, Encode(
                256, P10, A10, B10, SEED10, Q10, GY10
		    )); 
	    }
	    // получить именованные параметры
	    public static ECParameters Parameters(string oid) { return set[oid]; } 
    }
}
