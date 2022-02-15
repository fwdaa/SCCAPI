using System; 

namespace Aladdin.CAPI
{
    ///////////////////////////////////////////////////////////////////////////
    // Алгоритм проверки подписи на основе хэш-значения
    ///////////////////////////////////////////////////////////////////////////
    public class VerifyHashData : VerifyData
    {
        // алгоритм проверки подписи и алгоритм хэширования
        private VerifyHash verifyAlgorithm; private Hash hashAlgorithm;
        // параметры алгоритма хэширования 
        private ASN1.ISO.AlgorithmIdentifier hashParameters; 

        // конструктор
        public VerifyHashData(Hash hashAlgorithm, 
            ASN1.ISO.AlgorithmIdentifier hashParameters, VerifyHash verifyAlgorithm)
        { 
            // сохранить переданные параметры
            this.verifyAlgorithm = RefObject.AddRef(verifyAlgorithm); 
            this.hashAlgorithm   = RefObject.AddRef(hashAlgorithm  ); 
            
            // сохранить переданные параметры
            this.hashParameters = hashParameters; 
        }
        // освободить выделенные ресурсы
        protected override void OnDispose() 
        { 
            // освободить выделенные ресурсы
            RefObject.Release(hashAlgorithm); 
        
            // освободить выделенные ресурсы
            RefObject.Release(verifyAlgorithm); base.OnDispose();
        } 
        // алгоритм проверки подписи хэш-значения
        public override VerifyHash VerifyHashAlgorithm { get { return verifyAlgorithm; }}

	    // инициализировать алгоритм
	    public override void Init(IPublicKey publicKey, byte[] signature) 
	    {
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
            // получить хэш-значение
            byte[] hash = new byte[hashAlgorithm.HashSize]; hashAlgorithm.Finish(hash, 0); 

		    // проверить подпись хэш-значения
		    verifyAlgorithm.Verify(PublicKey, hashParameters, hash, Signature); 
	    }
    }
}
