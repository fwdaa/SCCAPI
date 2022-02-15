namespace Aladdin.CAPI.ANSI.Sign.RSA.PSS
{
    ///////////////////////////////////////////////////////////////////////////
    // Алгоритм проверки подписи RSA PSS
    ///////////////////////////////////////////////////////////////////////////
    public class VerifyHash : RSA.VerifyHash
    {
	    private CAPI.Hash	hashAlgorithm;	// алгоритм хэширования
	    private PRF 	    maskAlgorithm;	// функция генерации маски
	    private int		    saltLength;		// размер salt-значения
	    private byte	    trailerField;	// завершающий байт

        // способ возведения в степень
        private CAPI.Encipherment rawEncipherment; 
    
        // конструктор
        public VerifyHash(CAPI.Hash hashAlgorithm, PRF maskAlgorithm, int saltLength, byte trailerField)
        
            // сохранить переданные параметры
            : this(null, hashAlgorithm, maskAlgorithm, saltLength, trailerField) {} 
        
        // конструктор
	    public VerifyHash(CAPI.Encipherment rawEncipherment, 
            CAPI.Hash hashAlgorithm, PRF maskAlgorithm, int saltLength, byte trailerField)
	    {
            // сохранить переданные параметры
            this.rawEncipherment = RefObject.AddRef(rawEncipherment); 
        
            // сохранить переданные параметры
	        this.hashAlgorithm	= RefObject.AddRef(hashAlgorithm);
	        this.maskAlgorithm	= RefObject.AddRef(maskAlgorithm);

            // сохранить переданные параметры
	        this.saltLength = saltLength; this.trailerField = trailerField;
        }
        // освободить используемые ресурсы
        protected override void OnDispose()
        {
            // освободить используемые ресурсы
            RefObject.Release(rawEncipherment); RefObject.Release(maskAlgorithm); 
                
            // освободить используемые ресурсы
            RefObject.Release(hashAlgorithm); base.OnDispose();
        }
        // проверить подпись
        protected override void Check(byte[] encoded, int bits, 
            ASN1.ISO.AlgorithmIdentifier hashAlgorithm, byte[] hash) 
        {
            // проверить корректность подписи
            Encoding.Decode(this.hashAlgorithm, maskAlgorithm, 
                trailerField, encoded, bits - 1, saltLength, hash
            );  
        }
        // способ возведения в степень
        protected override byte[] Power(ANSI.RSA.IPublicKey publicKey, byte[] signature)
        {
            // выполнить возведение в степень
            if (rawEncipherment == null) return base.Power(publicKey, signature); 
        
            // выполнить возведение в степень
            return rawEncipherment.Encrypt(publicKey, null, signature); 
        }
    }
}
