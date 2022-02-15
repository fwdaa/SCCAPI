using System; 

namespace Aladdin.CAPI.STB.Sign.STB11762
{
    ///////////////////////////////////////////////////////////////////////
    // Алгоритм выработки подписи СТБ 1176.2 на основе хэш-значения СТБ 1176.1
    ///////////////////////////////////////////////////////////////////////
    public class SignDataPro : CAPI.SignData
    {
        // алгоритм подписи хэш-значения и алгоритм хэширования
        private CAPI.SignHash signAlgorithm; private CAPI.Hash hashAlgorithm;

        // конструктор
        public SignDataPro(CAPI.SignHash signAlgorithm) 
        {
            // сохранить переданные параметры
            this.signAlgorithm = RefObject.AddRef(signAlgorithm); hashAlgorithm = null;
        }
        // освободить выделенные ресурсы
        protected override void OnDispose() 
        { 
            // освободить выделенные ресурсы
            RefObject.Release(hashAlgorithm); 
        
            // освободить выделенные ресурсы
            RefObject.Release(signAlgorithm); base.OnDispose();
        } 
	    // инициализировать алгоритм
	    public override void Init(IPrivateKey privateKey, IRand rand) 
	    {
            // освободить выделенные ресурсы
            RefObject.Release(hashAlgorithm); hashAlgorithm = null; 

            // выполнить преобразование типа
            STB.STB11762.IBDSParameters parameters = 
                (STB.STB11762.IBDSParameters)privateKey.Parameters; 

            // создать алгоритм хэширования
            hashAlgorithm = CreateHashAlgorithm(privateKey, parameters.H); 

            // проверить наличие алгоритма хэширования
            if (hashAlgorithm == null) throw new NotSupportedException(); 

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
            byte[] signature = signAlgorithm.Sign(PrivateKey, rand, null, hash); 

            // освободить выделенные ресурсы
            RefObject.Release(hashAlgorithm); hashAlgorithm = null; 

            // вернуть вычисленную подпись
            base.Finish(rand); return signature; 
        }
        // создать алгоритм хэширования
        protected CAPI.Hash CreateHashAlgorithm(IPrivateKey privateKey, byte[] start) 
        { 
            // создать алгоритм хэширования
            return new Hash.STB11761(start);     
        }
    }
}
