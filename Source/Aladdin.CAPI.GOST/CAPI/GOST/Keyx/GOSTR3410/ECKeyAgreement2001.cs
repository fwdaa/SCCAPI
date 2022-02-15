using System; 

namespace Aladdin.CAPI.GOST.Keyx.GOSTR3410
{
    ///////////////////////////////////////////////////////////////////////////
    // Формирование общего ключа ГОСТ Р 34.10-2001
    ///////////////////////////////////////////////////////////////////////////
    public class ECKeyAgreement2001 : GOSTR3410.ECKeyAgreement
    {
        // конструктор
        public ECKeyAgreement2001(KeyDerive keyDerive) : base(keyDerive) {} 
        // конструктор
        public ECKeyAgreement2001() {} 

        // создать алгоритм хэширования
        protected override CAPI.Hash CreateHashAlgorithm(IPrivateKey privateKey, int keySize)
        {
            // преобразовать тип параметров
            GOST.GOSTR3410.INamedParameters parameters = 
                (GOST.GOSTR3410.INamedParameters)privateKey.Parameters; 
        
            // получить именованные параметры алгоритма
            ASN1.GOST.GOSTR3411ParamSet1994 namedParameters = 
                ASN1.GOST.GOSTR3411ParamSet1994.Parameters(parameters.HashOID);

            // раскодировать таблицу подстановок
            byte[] sbox = ASN1.GOST.GOST28147SBoxReference.DecodeSBox(namedParameters.HUZ); 

            // создать алгоритм хэширования
            return new Hash.GOSTR3411_1994(sbox, namedParameters.H0.Value, false);
        } 
    }
}