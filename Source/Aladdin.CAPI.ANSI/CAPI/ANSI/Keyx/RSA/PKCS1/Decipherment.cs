namespace Aladdin.CAPI.ANSI.Keyx.RSA.PKCS1
{
    ///////////////////////////////////////////////////////////////////////////
    // Алгоритм расшифрования RSA PKCS1.5
    ///////////////////////////////////////////////////////////////////////////
    public class Decipherment : RSA.Decipherment
	{
        // способ возведения в степень
        private CAPI.Decipherment rawDecipherment; 
    
        // конструктор
        public Decipherment() : this(null) {}
            
        // конструктор
        public Decipherment(CAPI.Decipherment rawDecipherment)
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
        // раскодировать данные
        protected override byte[] Decode(byte[] encoded, int bits)
        {
            // раскодировать данные
            return Encoding.Decode(encoded); 
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
