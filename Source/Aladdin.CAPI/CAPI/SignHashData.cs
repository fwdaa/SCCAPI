using System;

namespace Aladdin.CAPI
{
    ///////////////////////////////////////////////////////////////////////////
    // Алгоритм выработки подписи на основе хэш-значения
    ///////////////////////////////////////////////////////////////////////////
    public class SignHashData : SignData
    {
        // алгоритм подписи хэш-значения и алгоритм хэширования
        private SignHash signAlgorithm; private Hash hashAlgorithm;      
        // параметры алгоритма хэширования
        private ASN1.ISO.AlgorithmIdentifier hashParameters;

        // конструктор
        public SignHashData(Hash hashAlgorithm, 
            ASN1.ISO.AlgorithmIdentifier hashParameters, SignHash signAlgorithm)
        { 
            // сохранить переданные параметры
            this.signAlgorithm = RefObject.AddRef(signAlgorithm); 
            this.hashAlgorithm = RefObject.AddRef(hashAlgorithm); 
            
            // сохранить переданные параметры
            this.hashParameters = hashParameters; 
        }
        // освободить выделенные ресурсы
        protected override void OnDispose() 
        { 
            // освободить выделенные ресурсы
            RefObject.Release(hashAlgorithm); 
        
            // освободить выделенные ресурсы
            RefObject.Release(signAlgorithm); base.OnDispose();
        } 
        // алгоритм подписи хэш-значения
        public override SignHash SignHashAlgorithm { get { return signAlgorithm; }}

	    // инициализировать алгоритм
	    public override void Init(IPrivateKey privateKey, IRand rand) 
	    {
		    // инициализировать алгоритм хэширования
		    base.Init(privateKey, rand); hashAlgorithm.Init(); 
	    }
	    // обработать данные
	    public override void Update(byte[] data, int dataOff, int dataLen)
	    {
		    // прохэшировать данные
		    hashAlgorithm.Update(data, dataOff, dataLen); 
	    }
	    // получить подпись данных
        public override byte[] Finish(IRand rand)
	    {
            // получить хэш-значение
            byte[] hash = new byte[hashAlgorithm.HashSize]; hashAlgorithm.Finish(hash, 0);  
        
            // подписать хэш-значение
            byte[] signature = signAlgorithm.Sign(PrivateKey, rand, hashParameters, hash); 

            // освободить выделенные ресурсы
            base.Finish(rand); return signature; 
	    }
    }
}
