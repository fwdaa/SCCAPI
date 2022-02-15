using System; 

namespace Aladdin.CAPI.GOST.Sign.GOSTR3410
{
    ///////////////////////////////////////////////////////////////////////
    // Проверка подписи данных ГОСТ Р 34.10-1994
    ///////////////////////////////////////////////////////////////////////
    public class VerifyData1994 : VerifyData
    {
        // алгоритм проверки подписи и алгоритм хэширования
        private VerifyHash verifyAlgorithm; private CAPI.Hash hashAlgorithm;
    
        // конструктор
        public VerifyData1994(VerifyHash verifyAlgorithm)
        {
            // сохранить переданные параметры
            this.verifyAlgorithm = RefObject.AddRef(verifyAlgorithm); hashAlgorithm = null;
        }
        // освободить выделенные ресурсы
        protected override void OnDispose()
        {
            // освободить выделенные ресурсы
            RefObject.Release(hashAlgorithm); 
            
            // освободить выделенные ресурсы
            RefObject.Release(verifyAlgorithm); base.OnDispose();
        }
	    // инициализировать алгоритм
	    public override void Init(IPublicKey publicKey, byte[] signature) 
	    {
            // освободить выделенные ресурсы
            RefObject.Release(hashAlgorithm); hashAlgorithm = null; 

            // выполнить преобразование типа
            GOST.GOSTR3410.INamedParameters parameters = 
                (GOST.GOSTR3410.INamedParameters)publicKey.Parameters; 
        
            // создать алгоритм хэширования
            hashAlgorithm = CreateHashAlgorithm(parameters.HashOID); 

            // проверить наличие алгоритма хэширования
            if (hashAlgorithm == null) throw new NotSupportedException();
			
		    // инициализировать алгоритм хэширования
		    base.Init(publicKey, signature); hashAlgorithm.Init(); 
	    }
	    // обработать данные
	    public override void Update(byte[] data, int dataOff, int dataLen)
	    {
		    // прохэшировать данные
		    hashAlgorithm.Update(data, dataOff, dataLen); 
	    }
	    // получить подпись данных
        public override void Finish()
	    {
            // выполнить преобразование типа
            GOST.GOSTR3410.INamedParameters parameters = 
                (GOST.GOSTR3410.INamedParameters)PublicKey.Parameters; 

            // указать параметры алгоритма хэширования
            ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.GOST.OID.gostR3411_94), 
                new ASN1.ObjectIdentifier(parameters.HashOID)
            ); 
            // получить хэш-значение
            byte[] hash = new byte[hashAlgorithm.HashSize]; hashAlgorithm.Finish(hash, 0); 

		    // проверить подпись хэш-значения
		    try { verifyAlgorithm.Verify(PublicKey, hashParameters, hash, Signature); }

            // освободить выделенные ресурсы
            finally { RefObject.Release(hashAlgorithm); hashAlgorithm = null; } 
	    }
        // получить алгоритм хэширования
        protected virtual CAPI.Hash CreateHashAlgorithm(string hashOID)
        {
            // получить именованные параметры алгоритма
            ASN1.GOST.GOSTR3411ParamSet1994 namedParameters = 
                ASN1.GOST.GOSTR3411ParamSet1994.Parameters(hashOID);
        
            // раскодировать таблицу подстановок
            byte[] sbox = ASN1.GOST.GOST28147SBoxReference.DecodeSBox(namedParameters.HUZ); 

            // создать алгоритм хэширования
            return new Hash.GOSTR3411_1994(sbox, namedParameters.H0.Value, false);
        }
    }
}
