namespace Aladdin.CAPI.ANSI.Keyx.RSA.OAEP
{
    ///////////////////////////////////////////////////////////////////////////
    // Алгоритм зашифрования RSA OAEP
    ///////////////////////////////////////////////////////////////////////////
    public class Encipherment : RSA.Encipherment
    {
        private CAPI.Encipherment rawEncipherment;  // способ возведения в степень
	    private CAPI.Hash         hashAlgorithm;	// алгоритм хэширования
	    private PRF               maskAlgorithm;	// функция генерации маски
	    private byte[]            label;			// дополнительная метка

        // конструктор
        public Encipherment(CAPI.Hash hashAlgorithm, byte[] label) 
         
            // сохранить переданные параметры
            : this(null, hashAlgorithm, label) {} 
        
        // конструктор
        public Encipherment(CAPI.Hash hashAlgorithm, PRF maskAlgorithm, byte[] label) 
         
            // сохранить переданные параметры
            : this(null, hashAlgorithm, maskAlgorithm, label) {} 
        
        // конструктор
	    public Encipherment(CAPI.Encipherment rawEncipherment, 
            CAPI.Hash hashAlgorithm, byte[] label)
	    {
            // сохранить переданные параметры
            this.rawEncipherment = RefObject.AddRef(rawEncipherment); 

            // сохранить переданные параметры
	        this.hashAlgorithm	= RefObject.AddRef(hashAlgorithm);

            // создать алгоритм маскирования
	        this.maskAlgorithm	= new Derive.MGF1(hashAlgorithm); this.label = label;
        }
        // конструктор
	    public Encipherment(CAPI.Encipherment rawEncipherment, 
            CAPI.Hash hashAlgorithm, PRF maskAlgorithm, byte[] label)
	    {
            // сохранить переданные параметры
            this.rawEncipherment = RefObject.AddRef(rawEncipherment); 

            // сохранить переданные параметры
	        this.hashAlgorithm	= RefObject.AddRef(hashAlgorithm);
	        this.maskAlgorithm	= RefObject.AddRef(maskAlgorithm); this.label = label;
        }
        // освободить используемые ресурсы
        protected override void OnDispose()
        {
            // освободить используемые ресурсы
            RefObject.Release(rawEncipherment); RefObject.Release(maskAlgorithm);
                
            // освободить используемые ресурсы
            RefObject.Release(hashAlgorithm); base.OnDispose();
        }
        // закодировать данные
        protected override byte[] Encode(IRand rand, byte[] data, int bits) 
        {
            // закодировать данные
            return Encoding.Encode(hashAlgorithm, maskAlgorithm, label, rand, data, (bits + 7) / 8); 
        }
        // способ возведения в степень
        protected override byte[] Power(ANSI.RSA.IPublicKey publicKey, byte[] data)
        {
            // выполнить возведение в степень
            if (rawEncipherment == null) return base.Power(publicKey, data); 
        
            // выполнить возведение в степень
            return rawEncipherment.Encrypt(publicKey, null, data); 
        }
    }
}
