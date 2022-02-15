namespace Aladdin.CAPI.ANSI.Keyx.RSA.OAEP
{
    ///////////////////////////////////////////////////////////////////////////
    // Алгоритм расшифрования RSA OAEP
    ///////////////////////////////////////////////////////////////////////////
    public class Decipherment : RSA.Decipherment
    {
        private CAPI.Hash   hashAlgorithm;	// алгоритм хэширования
        private PRF 	    maskAlgorithm;	// функция генерации маски
        private byte[]	    label;			// дополнительная метка

        // способ возведения в степень
        private CAPI.Decipherment rawDecipherment; 
    
        // конструктор
        public Decipherment(CAPI.Hash hashAlgorithm, byte[] label)
        
            // сохранить переданные параметры
            : this(null, hashAlgorithm, label) {} 
        
        // конструктор
        public Decipherment(CAPI.Hash hashAlgorithm, PRF maskAlgorithm, byte[] label)
        
            // сохранить переданные параметры
            : this(null, hashAlgorithm, maskAlgorithm, label) {} 
        
        // конструктор
        public Decipherment(CAPI.Decipherment rawDecipherment, 
            CAPI.Hash hashAlgorithm, byte[] label)
        {
            // сохранить переданные параметры
            this.rawDecipherment = RefObject.AddRef(rawDecipherment); 

            // сохранить переданные параметры
	        this.hashAlgorithm	= RefObject.AddRef(hashAlgorithm);

            // создать алгоритм маскирования
	        this.maskAlgorithm	= new Derive.MGF1(hashAlgorithm); this.label = label;
        }
        // конструктор
        public Decipherment(CAPI.Decipherment rawDecipherment, 
            CAPI.Hash hashAlgorithm, PRF maskAlgorithm, byte[] label)
        {
            // сохранить переданные параметры
            this.rawDecipherment = RefObject.AddRef(rawDecipherment); 

            // сохранить переданные параметры
	        this.hashAlgorithm	= RefObject.AddRef(hashAlgorithm);
	        this.maskAlgorithm	= RefObject.AddRef(maskAlgorithm);

            // сохранить переданные параметры
	        this.label = label;
        }
        // освободить используемые ресурсы
        protected override void OnDispose()
        {
            // освободить используемые ресурсы
            RefObject.Release(rawDecipherment); RefObject.Release(maskAlgorithm); 
                
            // освободить используемые ресурсы
            RefObject.Release(hashAlgorithm); base.OnDispose();
        }
        // раскодировать данные
        protected override byte[] Decode(byte[] encoded, int bits) 
        {
            // раскодировать данные
            return Encoding.Decode(hashAlgorithm, maskAlgorithm, label, encoded); 
        }
        // способ возведения в степень
        protected override byte[] Power(ANSI.RSA.IPrivateKey privateKey, byte[] data)
        {
            // выполнить возведение в степень
            if (rawDecipherment == null) return base.Power(privateKey, data); 
        
            // выполнить возведение в степень
            return rawDecipherment.Decrypt(privateKey, data); 
        }
    }
}
