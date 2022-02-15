using System; 

namespace Aladdin.CAPI.ANSI.Sign.RSA.PSS
{
    ///////////////////////////////////////////////////////////////////////////
    // Алгоритм подписи RSA PSS
    ///////////////////////////////////////////////////////////////////////////
    public class SignHash : RSA.SignHash
    {
	    private CAPI.Hash	hashAlgorithm;	// алгоритм хэширования
	    private PRF	        maskAlgorithm;	// функция генерации маски
	    private int		    saltLength;		// размер salt-значения
	    private byte	    trailerField;	// завершающий байт

        // способ возведения в степень
        private CAPI.Decipherment rawDecipherment; 
    
        // конструктор
        public SignHash(CAPI.Hash hashAlgorithm, int saltLength, byte trailerField)
        
            // сохранить переданные параметры
            : this(null, hashAlgorithm, saltLength, trailerField) {} 

        // конструктор
        public SignHash(CAPI.Hash hashAlgorithm, PRF maskAlgorithm, int saltLength, byte trailerField)
        
            // сохранить переданные параметры
            : this(null, hashAlgorithm, maskAlgorithm, saltLength, trailerField) {} 
        
	    public SignHash(CAPI.Decipherment rawDecipherment, 
            CAPI.Hash hashAlgorithm, int saltLength, byte trailerField)
	    {
            // сохранить переданные параметры
            this.rawDecipherment = RefObject.AddRef(rawDecipherment); 

            // сохранить переданные параметры
	        this.hashAlgorithm = RefObject.AddRef(hashAlgorithm);

            // создать алгоритм маскирования
	        this.maskAlgorithm = new Derive.MGF1(hashAlgorithm);

            // сохранить переданные параметры
            this.saltLength	= saltLength; this.trailerField	= trailerField;
        }
	    public SignHash(CAPI.Decipherment rawDecipherment, 
            CAPI.Hash hashAlgorithm, PRF maskAlgorithm, int saltLength, byte trailerField)
	    {
            // сохранить переданные параметры
            this.rawDecipherment = RefObject.AddRef(rawDecipherment); 

            // сохранить переданные параметры
	        this.hashAlgorithm	= RefObject.AddRef(hashAlgorithm);
	        this.maskAlgorithm	= RefObject.AddRef(maskAlgorithm);

            // сохранить переданные параметры
            this.saltLength	= saltLength; this.trailerField	= trailerField;
        }
        // освободить используемые ресурсы
        protected override void OnDispose()
        {
            // освободить используемые ресурсы
            RefObject.Release(rawDecipherment); RefObject.Release(maskAlgorithm); 
                
            // освободить используемые ресурсы
            RefObject.Release(hashAlgorithm); base.OnDispose();
        }
        // закодировать данные
        protected override byte[] Encode(IRand rand, 
            ASN1.ISO.AlgorithmIdentifier hashAlgorithm, byte[] hash, int bits)
        {
            return Encoding.Encode(rand, this.hashAlgorithm, 
                maskAlgorithm, trailerField, bits - 1, saltLength, hash
            ); 
        }
        // способ возведения в степень
        protected override byte[] Power(ANSI.RSA.IPrivateKey privateKey, IRand rand, byte[] hash)
        {
            // выполнить возведение в степень
            if (rawDecipherment == null) return base.Power(privateKey, rand, hash); 
        
            // выполнить возведение в степень
            return rawDecipherment.Decrypt(privateKey, hash); 
        }
    }
}
