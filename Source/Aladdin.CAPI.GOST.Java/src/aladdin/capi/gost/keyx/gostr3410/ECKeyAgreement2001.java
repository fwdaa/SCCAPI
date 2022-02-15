package aladdin.capi.gost.keyx.gostr3410;
import aladdin.asn1.gost.*;
import aladdin.capi.*; 
import java.io.*;

///////////////////////////////////////////////////////////////////////////
// Формирование общего ключа ГОСТ Р 34.10-2001
///////////////////////////////////////////////////////////////////////////
public class ECKeyAgreement2001 extends ECKeyAgreement
{
    // конструктор
    public ECKeyAgreement2001(KeyDerive keyDerive) { super(keyDerive); }
    // конструктор
    public ECKeyAgreement2001() { super(); }

    // создать алгоритм хэширования
    @Override protected Hash createHashAlgorithm(
        IPrivateKey privateKey, int keySize) throws IOException
    {
        // преобразовать тип параметров
        aladdin.capi.gost.gostr3410.INamedParameters parameters = 
            (aladdin.capi.gost.gostr3410.INamedParameters)privateKey.parameters(); 
        
        // получить именованные параметры алгоритма
        GOSTR3411ParamSet1994 namedParameters = 
            GOSTR3411ParamSet1994.parameters(parameters.hashOID());

        // раскодировать таблицу подстановок
        byte[] sbox = GOST28147SBoxReference.decodeSBox(namedParameters.huz()); 

        // создать алгоритм хэширования
        return new aladdin.capi.gost.hash.GOSTR3411_1994(
            sbox, namedParameters.h0().value(), false
        );
    } 
}
