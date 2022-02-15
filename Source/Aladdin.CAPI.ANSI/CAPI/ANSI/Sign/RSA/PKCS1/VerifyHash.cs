namespace Aladdin.CAPI.ANSI.Sign.RSA.PKCS1
{
    ///////////////////////////////////////////////////////////////////////////
    // Алгоритм проверки подписи RSA PKCS1.5
    ///////////////////////////////////////////////////////////////////////////
	public class VerifyHash : RSA.VerifyHash
	{
        // способ возведения в степень
        private CAPI.Encipherment rawEncipherment; 
    
        // конструктор
        public VerifyHash() : this(null) {}
            
        // конструктор
        public VerifyHash(CAPI.Encipherment rawEncipherment)
        {
            // сохранить переданные параметры
            this.rawEncipherment = RefObject.AddRef(rawEncipherment); 
        }
        // деструктор
        protected override void OnDispose()
        {
            // освободить выделенные ресурсы
            RefObject.Release(rawEncipherment); base.OnDispose();
        }
        // проверить подпись
        protected override void Check(byte[] encoded, int bits, 
            ASN1.ISO.AlgorithmIdentifier hashAlgorithm, byte[] hash) 
        {
            // закодировать хэш-значение 
            ASN1.ISO.PKCS.DigestInfo digestInfo = new ASN1.ISO.PKCS.DigestInfo(
                hashAlgorithm, new ASN1.OctetString(hash)
            ); 
            // закодировать хэш-значение 
            byte[] check = Encoding.Encode(digestInfo.Encoded, encoded.Length); 
        
            // проверить совпадение значений
            if (!Arrays.Equals(check, encoded)) throw new SignatureException();  
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
