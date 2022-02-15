namespace Aladdin.CAPI.ANSI.Sign.RSA.PKCS1
{
    ///////////////////////////////////////////////////////////////////////////
    // Алгоритм подписи RSA PKCS1.5
    ///////////////////////////////////////////////////////////////////////////
    public class SignHash : RSA.SignHash
    {
        // способ возведения в степень
        private CAPI.Decipherment rawDecipherment; 
    
        // конструктор
        public SignHash() : this(null) {}
            
        // конструктор
        public SignHash(CAPI.Decipherment rawDecipherment)
        {
            // сохранить переданные параметры
            this.rawDecipherment = RefObject.AddRef(rawDecipherment); 
        }
        // деструктор
        protected override void OnDispose()
        {
            // освободить выделенные ресурсы
            RefObject.Release(rawDecipherment); base.OnDispose();
        }
        // закодировать данные
        protected override byte[] Encode(IRand rand, 
            ASN1.ISO.AlgorithmIdentifier hashAlgorithm, byte[] hash, int bits) 
        {
            // закодировать хэш-значение 
            ASN1.ISO.PKCS.DigestInfo digestInfo = new ASN1.ISO.PKCS.DigestInfo(
                hashAlgorithm, new ASN1.OctetString(hash)
            ); 
            // закодировать данные
            return Encoding.Encode(digestInfo.Encoded, (bits + 7) / 8); 
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
