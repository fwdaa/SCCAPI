using System;

namespace Aladdin.CAPI.KZ.Keyx.Tumar.GOST34310
{
    ///////////////////////////////////////////////////////////////////////////////
    // Алгоритм формирования общего ключа
    ///////////////////////////////////////////////////////////////////////////////
    public class KeyAgreement : GOST.Keyx.GOSTR3410.ECKeyAgreement2001
    {
        // создать алгоритм хэширования
        protected override Hash CreateHashAlgorithm(IPrivateKey privateKey, int keySize)
        {
            // получить таблицу подстановок
            byte[] sbox = ASN1.KZ.SBoxReference.CryptoProHashSBox(); 
        
            // создать алгоритм хэширования
            return new GOST.Hash.GOSTR3411_1994(sbox, new byte[32], false); 
        } 
    }
}
