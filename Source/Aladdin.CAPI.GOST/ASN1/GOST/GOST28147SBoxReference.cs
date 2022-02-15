﻿using System;
using System.Collections.Generic;

namespace Aladdin.ASN1.GOST
{
    public static class GOST28147SBoxReference
    {
	    /////////////////////////////////////////////////////////////////////////////
	    // Раскодировать таблицу подстановок
	    /////////////////////////////////////////////////////////////////////////////
	    public static byte[] DecodeSBox(ASN1.OctetString encoded)
	    {
		    // выделить память для таблицы подстановок
		    byte[] sbox = new byte[128]; byte[] value = encoded.Value; 
        
            // для всех закодированных байтов
            for (int i = 0; i < 16; i++) for (int j = 0; j < 4; j++)
		    {
			    // раскодировать таблицу подстановок
			    sbox[j * 32 + i +  0] = (byte)((value[i * 4 + j] & 0xF0) >> 4); 
			    sbox[j * 32 + i + 16] = (byte)((value[i * 4 + j] & 0x0F)     ); 
		    }
		    return sbox; 
	    }
	    /////////////////////////////////////////////////////////////////////////////
	    // Именованные таблицы подстановок
	    /////////////////////////////////////////////////////////////////////////////
	    private static readonly byte[] EUZ_TEST = new byte[] {
		    (byte)0x4C, (byte)0xDE, (byte)0x38, (byte)0x9C, 
            (byte)0x29, (byte)0x89, (byte)0xEF, (byte)0xB6, 
    	    (byte)0xFF, (byte)0xEB, (byte)0x56, (byte)0xC5, 
            (byte)0x5E, (byte)0xC2, (byte)0x9B, (byte)0x02,
		    (byte)0x98, (byte)0x75, (byte)0x61, (byte)0x3B, 
            (byte)0x11, (byte)0x3F, (byte)0x89, (byte)0x60, 
		    (byte)0x03, (byte)0x97, (byte)0x0C, (byte)0x79, 
            (byte)0x8A, (byte)0xA1, (byte)0xD5, (byte)0x5D,
		    (byte)0xE2, (byte)0x10, (byte)0xAD, (byte)0x43, 
            (byte)0x37, (byte)0x5D, (byte)0xB3, (byte)0x8E, 
		    (byte)0xB4, (byte)0x2C, (byte)0x77, (byte)0xE7, 
            (byte)0xCD, (byte)0x46, (byte)0xCA, (byte)0xFA,
		    (byte)0xD6, (byte)0x6A, (byte)0x20, (byte)0x1F, 
            (byte)0x70, (byte)0xF4, (byte)0x1E, (byte)0xA4, 
		    (byte)0xAB, (byte)0x03, (byte)0xF2, (byte)0x21, 
            (byte)0x65, (byte)0xB8, (byte)0x44, (byte)0xD8,
	    }; 
	    private static readonly byte[] EUZ_A = new byte[] {
		    (byte)0x93, (byte)0xEE, (byte)0xB3, (byte)0x1B, 
            (byte)0x67, (byte)0x47, (byte)0x5A, (byte)0xDA, 
		    (byte)0x3E, (byte)0x6A, (byte)0x1D, (byte)0x2F, 
            (byte)0x29, (byte)0x2C, (byte)0x9C, (byte)0x95,
		    (byte)0x88, (byte)0xBD, (byte)0x81, (byte)0x70, 
            (byte)0xBA, (byte)0x31, (byte)0xD2, (byte)0xAC, 
		    (byte)0x1F, (byte)0xD3, (byte)0xF0, (byte)0x6E, 
            (byte)0x70, (byte)0x89, (byte)0x0B, (byte)0x08,
		    (byte)0xA5, (byte)0xC0, (byte)0xE7, (byte)0x86, 
            (byte)0x42, (byte)0xF2, (byte)0x45, (byte)0xC2, 
		    (byte)0xE6, (byte)0x5B, (byte)0x29, (byte)0x43, 
            (byte)0xFC, (byte)0xA4, (byte)0x34, (byte)0x59,
		    (byte)0xCB, (byte)0x0F, (byte)0xC8, (byte)0xF1, 
            (byte)0x04, (byte)0x78, (byte)0x7F, (byte)0x37, 
		    (byte)0xDD, (byte)0x15, (byte)0xAE, (byte)0xBD, 
            (byte)0x51, (byte)0x96, (byte)0x66, (byte)0xE4,
	    }; 
	    private static readonly byte[] EUZ_B = new byte[] {
		    (byte)0x80, (byte)0xE7, (byte)0x28, (byte)0x50, 
            (byte)0x41, (byte)0xC5, (byte)0x73, (byte)0x24, 
		    (byte)0xB2, (byte)0x00, (byte)0xC2, (byte)0xAB, 
            (byte)0x1A, (byte)0xAD, (byte)0xF6, (byte)0xBE,
		    (byte)0x34, (byte)0x9B, (byte)0x94, (byte)0x98, 
            (byte)0x5D, (byte)0x26, (byte)0x5D, (byte)0x13,
		    (byte)0x05, (byte)0xD1, (byte)0xAE, (byte)0xC7, 
            (byte)0x9C, (byte)0xB2, (byte)0xBB, (byte)0x31,
    	    (byte)0x29, (byte)0x73, (byte)0x1C, (byte)0x7A, 
            (byte)0xE7, (byte)0x5A, (byte)0x41, (byte)0x42, 
		    (byte)0xA3, (byte)0x8C, (byte)0x07, (byte)0xD9, 
            (byte)0xCF, (byte)0xFF, (byte)0xDF, (byte)0x06,
		    (byte)0xDB, (byte)0x34, (byte)0x6A, (byte)0x6F, 
            (byte)0x68, (byte)0x6E, (byte)0x80, (byte)0xFD,
		    (byte)0x76, (byte)0x19, (byte)0xE9, (byte)0x85, 
            (byte)0xFE, (byte)0x48, (byte)0x35, (byte)0xEC,
	    };
	    private static readonly byte[] EUZ_C = new byte[] {
		    (byte)0x10, (byte)0x83, (byte)0x8C, (byte)0xA7, 
            (byte)0xB1, (byte)0x26, (byte)0xD9, (byte)0x94, 
		    (byte)0xC7, (byte)0x50, (byte)0xBB, (byte)0x60, 
            (byte)0x2D, (byte)0x01, (byte)0x01, (byte)0x85,
		    (byte)0x9B, (byte)0x45, (byte)0x48, (byte)0xDA, 
            (byte)0xD4, (byte)0x9D, (byte)0x5E, (byte)0xE2, 
		    (byte)0x05, (byte)0xFA, (byte)0x12, (byte)0x2F, 
            (byte)0xF2, (byte)0xA8, (byte)0x24, (byte)0x0E,
		    (byte)0x48, (byte)0x3B, (byte)0x97, (byte)0xFC, 
            (byte)0x5E, (byte)0x72, (byte)0x33, (byte)0x36, 
		    (byte)0x8F, (byte)0xC9, (byte)0xC6, (byte)0x51, 
            (byte)0xEC, (byte)0xD7, (byte)0xE5, (byte)0xBB,
		    (byte)0xA9, (byte)0x6E, (byte)0x6A, (byte)0x4D, 
            (byte)0x7A, (byte)0xEF, (byte)0xF0, (byte)0x19, 
		    (byte)0x66, (byte)0x1C, (byte)0xAF, (byte)0xC3, 
            (byte)0x33, (byte)0xB4, (byte)0x7D, (byte)0x78,
	    }; 
	    // таблица подстановок
	    private static readonly byte[] EUZ_D = new byte[] {
		    (byte)0xFB, (byte)0x11, (byte)0x08, (byte)0x31, 
            (byte)0xC6, (byte)0xC5, (byte)0xC0, (byte)0x0A, 
		    (byte)0x23, (byte)0xBE, (byte)0x8F, (byte)0x66, 
            (byte)0xA4, (byte)0x0C, (byte)0x93, (byte)0xF8,
		    (byte)0x6C, (byte)0xFA, (byte)0xD2, (byte)0x1F, 
            (byte)0x4F, (byte)0xE7, (byte)0x25, (byte)0xEB, 
		    (byte)0x5E, (byte)0x60, (byte)0xAE, (byte)0x90, 
            (byte)0x02, (byte)0x5D, (byte)0xBB, (byte)0x24,
		    (byte)0x77, (byte)0xA6, (byte)0x71, (byte)0xDC, 
            (byte)0x9D, (byte)0xD2, (byte)0x3A, (byte)0x83, 
		    (byte)0xE8, (byte)0x4B, (byte)0x64, (byte)0xC5, 
            (byte)0xD0, (byte)0x84, (byte)0x57, (byte)0x49,
		    (byte)0x15, (byte)0x99, (byte)0x4C, (byte)0xB7, 
            (byte)0xBA, (byte)0x33, (byte)0xE9, (byte)0xAD, 
		    (byte)0x89, (byte)0x7F, (byte)0xFD, (byte)0x52, 
            (byte)0x31, (byte)0x28, (byte)0x16, (byte)0x7E,
	    }; 
        private static readonly byte[] EUZ_TK26_Z = new byte[] {
            (byte)0xc6, (byte)0xbc, (byte)0x75, (byte)0x81, 
            (byte)0x48, (byte)0x38, (byte)0xfd, (byte)0xe7, 
            (byte)0x62, (byte)0x52, (byte)0x5f, (byte)0x2e, 
            (byte)0x23, (byte)0x81, (byte)0xa6, (byte)0x5d,
            (byte)0xa9, (byte)0x2d, (byte)0x89, (byte)0x60, 
            (byte)0x5a, (byte)0xf4, (byte)0x12, (byte)0x95, 
            (byte)0xb5, (byte)0xaf, (byte)0x6c, (byte)0x18, 
            (byte)0x9c, (byte)0xd6, (byte)0xda, (byte)0xc3,
            (byte)0xe1, (byte)0xe7, (byte)0x0b, (byte)0xf4, 
            (byte)0x8e, (byte)0x10, (byte)0x97, (byte)0x4f, 
            (byte)0xd4, (byte)0x7a, (byte)0x38, (byte)0xba, 
            (byte)0x77, (byte)0x45, (byte)0xe1, (byte)0x06,
            (byte)0x0b, (byte)0xc3, (byte)0xb4, (byte)0xd9, 
            (byte)0x3d, (byte)0x9e, (byte)0x43, (byte)0xac, 
            (byte)0xf0, (byte)0x69, (byte)0x2e, (byte)0x3b, 
            (byte)0x1f, (byte)0x0b, (byte)0xc0, (byte)0x72,
        }; 
	    private static readonly byte[] HUZ_TEST = new byte[] {
		    (byte)0x4E, (byte)0x57, (byte)0x64, (byte)0xD1, 
            (byte)0xAB, (byte)0x8D, (byte)0xCB, (byte)0xBF, 
		    (byte)0x94, (byte)0x1A, (byte)0x7A, (byte)0x4D, 
            (byte)0x2C, (byte)0xD1, (byte)0x10, (byte)0x10,
		    (byte)0xD6, (byte)0xA0, (byte)0x57, (byte)0x35, 
            (byte)0x8D, (byte)0x38, (byte)0xF2, (byte)0xF7, 
		    (byte)0x0F, (byte)0x49, (byte)0xD1, (byte)0x5A, 
            (byte)0xEA, (byte)0x2F, (byte)0x8D, (byte)0x94,
		    (byte)0x62, (byte)0xEE, (byte)0x43, (byte)0x09, 
            (byte)0xB3, (byte)0xF4, (byte)0xA6, (byte)0xA2, 
		    (byte)0x18, (byte)0xC6, (byte)0x98, (byte)0xE3, 
            (byte)0xC1, (byte)0x7C, (byte)0xE5, (byte)0x7E,
		    (byte)0x70, (byte)0x6B, (byte)0x09, (byte)0x66, 
            (byte)0xF7, (byte)0x02, (byte)0x3C, (byte)0x8B, 
		    (byte)0x55, (byte)0x95, (byte)0xBF, (byte)0x28, 
            (byte)0x39, (byte)0xB3, (byte)0x2E, (byte)0xCC,
	    }; 
	    private static readonly byte[] HUZ_CRYPTOPRO = new byte[] {
		    (byte)0xA5, (byte)0x74, (byte)0x77, (byte)0xD1, 
            (byte)0x4F, (byte)0xFA, (byte)0x66, (byte)0xE3, 
		    (byte)0x54, (byte)0xC7, (byte)0x42, (byte)0x4A, 
            (byte)0x60, (byte)0xEC, (byte)0xB4, (byte)0x19,
		    (byte)0x82, (byte)0x90, (byte)0x9D, (byte)0x75, 
            (byte)0x1D, (byte)0x4F, (byte)0xC9, (byte)0x0B,
		    (byte)0x3B, (byte)0x12, (byte)0x2F, (byte)0x54, 
            (byte)0x79, (byte)0x08, (byte)0xA0, (byte)0xAF,
		    (byte)0xD1, (byte)0x3E, (byte)0x1A, (byte)0x38, 
            (byte)0xC7, (byte)0xB1, (byte)0x81, (byte)0xC6, 
		    (byte)0xE6, (byte)0x56, (byte)0x05, (byte)0x87, 
            (byte)0x03, (byte)0x25, (byte)0xEB, (byte)0xFE,
		    (byte)0x9C, (byte)0x6D, (byte)0xF8, (byte)0x6D, 
            (byte)0x2E, (byte)0xAB, (byte)0xDE, (byte)0x20, 
		    (byte)0xBA, (byte)0x89, (byte)0x3C, (byte)0x92, 
            (byte)0xF8, (byte)0xD3, (byte)0x53, (byte)0xBC,
	    }; 
	    // таблица именованных параметров
	    private static readonly Dictionary<String, ASN1.OctetString> set = 
            new Dictionary<String, ASN1.OctetString>(); 

	    static GOST28147SBoxReference() {
		    set.Add(ASN1.GOST.OID.encrypts_test   , new ASN1.OctetString(EUZ_TEST     )); 
		    set.Add(ASN1.GOST.OID.encrypts_A      , new ASN1.OctetString(EUZ_A        )); 
		    set.Add(ASN1.GOST.OID.encrypts_B      , new ASN1.OctetString(EUZ_B        )); 
		    set.Add(ASN1.GOST.OID.encrypts_C      , new ASN1.OctetString(EUZ_C        )); 
		    set.Add(ASN1.GOST.OID.encrypts_D      , new ASN1.OctetString(EUZ_D        )); 
		    set.Add(ASN1.GOST.OID.encrypts_tc26_z , new ASN1.OctetString(EUZ_TK26_Z   )); 
		    set.Add(ASN1.GOST.OID.hashes_test     , new ASN1.OctetString(HUZ_TEST     )); 
		    set.Add(ASN1.GOST.OID.hashes_cryptopro, new ASN1.OctetString(HUZ_CRYPTOPRO)); 
	    }
	    // получить именованные параметры
	    public static ASN1.OctetString Parameters(string oid) { return set[oid]; } 
    }
}
