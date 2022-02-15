package aladdin.capi.kz.keyx.tumar.gost34310;
import aladdin.asn1.kz.*;
import aladdin.capi.*; 
import java.io.*;

///////////////////////////////////////////////////////////////////////////////
// Алгоритм формирования общего ключа
///////////////////////////////////////////////////////////////////////////////
public class KeyAgreement extends aladdin.capi.gost.keyx.gostr3410.ECKeyAgreement2001
{
    // создать алгоритм хэширования
    @Override protected Hash createHashAlgorithm(
        IPrivateKey privateKey, int keySize) throws IOException
    {
        // получить таблицу подстановок
        byte[] sbox = SBoxReference.cryptoproHashSBox(); 
        
        // создать алгоритм хэширования
        return new aladdin.capi.gost.hash.GOSTR3411_1994(sbox, new byte[32], false); 
    } 
}
