using System; 
using System.Collections.Generic; 

namespace Aladdin.ASN1.STB
{
    public static class SBoxReference
    {
	    /////////////////////////////////////////////////////////////////////////////
	    // Раскодировать таблицу подстановок
	    /////////////////////////////////////////////////////////////////////////////
	    public static byte[] DecodeSBox(OctetString encoded)
	    {
		    // выделить память для таблицы подстановок
		    byte[] sbox = new byte[128]; byte[] value = encoded.Value; 
        
            // для всех закодированных байтов
            for (int i = 0; i < 64; i++) 
		    {
			    // раскодировать таблицу подстановок
			    sbox[i * 2 + 0] = (byte)((value[i] & 0xF0) >> 4); 
			    sbox[i * 2 + 1] = (byte)((value[i] & 0x0F)     ); 
		    }
		    return sbox; 
	    }
	    /////////////////////////////////////////////////////////////////////////////
	    // Именованные таблицы подстановок
	    /////////////////////////////////////////////////////////////////////////////
	    private static readonly byte[] GOST28147_1 = new byte[] {
            (byte)0x26, (byte)0x3E, (byte)0xCF, (byte)0x75, 
            (byte)0xBD, (byte)0x89, (byte)0xA0, (byte)0x41,
            (byte)0x8C, (byte)0x96, (byte)0xA7, (byte)0xD1, 
            (byte)0x3B, (byte)0xEF, (byte)0x24, (byte)0x05,
            (byte)0x15, (byte)0x4D, (byte)0x38, (byte)0x0E, 
            (byte)0xC6, (byte)0x72, (byte)0x9F, (byte)0xBA,
            (byte)0x40, (byte)0x5A, (byte)0x2B, (byte)0x19, 
            (byte)0xF3, (byte)0x67, (byte)0xEC, (byte)0x8D,
            (byte)0x79, (byte)0x6B, (byte)0xFA, (byte)0x8C, 
            (byte)0x4E, (byte)0x10, (byte)0x53, (byte)0xD2,
            (byte)0xE8, (byte)0xF2, (byte)0x63, (byte)0x9D, 
            (byte)0x57, (byte)0x01, (byte)0x4A, (byte)0xCB,
            (byte)0x9D, (byte)0x85, (byte)0xB4, (byte)0xC2, 
            (byte)0x0A, (byte)0xFE, (byte)0x17, (byte)0x36,
            (byte)0xBF, (byte)0xA8, (byte)0x1E, (byte)0x36, 
            (byte)0x90, (byte)0x45, (byte)0xD2, (byte)0x7C
	    }; 
	    // таблица именованных параметров
	    private static readonly Dictionary<String, OctetString> set = 
            new Dictionary<String, OctetString>(); 
	    static SBoxReference()
        {
		    set.Add(OID.gost28147_sblock_1, new OctetString(GOST28147_1)); 
	    }
	    // получить именованные параметры
	    public static OctetString Parameters(string oid) { return set[oid]; } 

	    // раскодировать таблицу подстановок
	    public static byte[] DecodeSBox(string oid) { return DecodeSBox(Parameters(oid)); }
    }
}