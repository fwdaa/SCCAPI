namespace Aladdin.ASN1.KZ
{ 
    public static class SBoxReference
    {
	    // получить таблицу подстановок
	    public static byte[] GammaCipherSBox() 
        { 
            return new byte[] { 
                 6, 12,  8,  4, 15,  1,  9,  2, 10, 14,  5,  7,  0, 11,  3, 13, 
                 5, 15,  4, 13,  0,  7, 10,  3, 14, 12,  1,  2,  8,  6, 11,  9, 
                10,  8,  1, 14, 11,  2,  3,  0, 15,  6,  4,  9,  7, 12,  5, 13, 
                 7, 15, 10, 11,  3,  1, 13,  8,  4,  5, 12,  9,  0, 14,  2,  6, 
                 3, 12,  7, 14, 13,  1,  5, 15,  9,  4,  8,  2, 11,  0,  6, 10, 
                 9, 14, 11,  2, 13,  0, 12, 15,  1,  6,  8,  4,  3, 10,  7,  5, 
                12,  3,  6,  9,  5,  8, 10,  2,  0, 13, 15,  7,  1, 14, 11,  4, 
                15,  9,  7,  8,  1, 14,  4,  6, 11,  0, 12,  2, 13,  3, 10,  5 
            };        
        } 
	    // получить таблицу подстановок
	    public static byte[] GammaHashSBox() 
        { 
            // указать идентификатор параметров хэширования
            string hashOID = ASN1.GOST.OID.hashes_test; 
        
            // получить именованные параметры алгоритма
            ASN1.GOST.GOSTR3411ParamSet1994 parameters = ASN1.GOST.GOSTR3411ParamSet1994.Parameters(hashOID);
 
            // раскодировать таблицу подстановок
            return ASN1.GOST.GOST28147SBoxReference.DecodeSBox(parameters.HUZ); 
        } 
	    public static byte[] CryptoProHashSBox() 
        { 
            // указать идентификатор подстановок ГОСТ
            string hashOID = ASN1.GOST.OID.hashes_cryptopro; 
        
            // получить именованные параметры алгоритма
            ASN1.GOST.GOSTR3411ParamSet1994 parameters = ASN1.GOST.GOSTR3411ParamSet1994.Parameters(hashOID);
 
            // раскодировать таблицу подстановок
            return ASN1.GOST.GOST28147SBoxReference.DecodeSBox(parameters.HUZ); 
        } 
    }
}
