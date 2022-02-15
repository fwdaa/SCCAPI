namespace Aladdin.CAPI.ANSI.Keyx.RSA.PKCS1
{
    ///////////////////////////////////////////////////////////////////////////
    // Алгоритм зашифрования RSA PKCS1.5
    ///////////////////////////////////////////////////////////////////////////
    public class Encipherment : RSA.Encipherment
    {
        // способ возведения в степень
        private CAPI.Encipherment rawEncipherment; 
    
        // конструктор
        public Encipherment() : this(null) {}
            
        // конструктор
        public Encipherment(CAPI.Encipherment rawEncipherment)
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
        // закодировать данные
        protected override byte[] Encode(IRand rand, byte[] data, int bits)
        {
            // закодировать данные
            return Encoding.Encode(rand, data, (bits + 7) / 8); 
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
