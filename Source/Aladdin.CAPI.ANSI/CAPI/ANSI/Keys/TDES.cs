using System; 

namespace Aladdin.CAPI.ANSI.Keys
{
    ///////////////////////////////////////////////////////////////////////////
    // Ключ TDES
    ///////////////////////////////////////////////////////////////////////////
    public class TDES : SecretKeyFactory
    {
        // конструктор
        public TDES(int[] keySizes) : base(keySizes) {}
        // конструктор
        public TDES() : base(new int[] { 16, 24 }) {}
    
        // ограничить размер ключей
        public override SecretKeyFactory Narrow(int[] keySizes) 
        { 
            // ограничить размер ключей
            return new TDES(keySizes); 
        }
        // создать ключ
        public override ISecretKey Create(byte[] value) 
        { 
            // создать копию значения
            value = (byte[])value.Clone(); 
        
            // выполнить нормализацию ключа
            DES.AdjustParity(value, 0, value.Length); 
        
            // создать ключ
            return base.Create(value); 
        }
        // сгенерировать ключ
        public override ISecretKey Generate(IRand rand, int keySize) 
        {
            // проверить размер ключа
            if (!CAPI.KeySizes.Contains(KeySizes, keySize)) 
            {
                // при ошибке выбросить исключение
                throw new NotSupportedException();
            } 
            // сгенерировать ключ
            byte[] value = new byte[keySize]; rand.Generate(value, 0, keySize);

            // выполнить нормализацию ключа
            DES.AdjustParity(value, 0, keySize); 

            // вернуть сгенерированный ключ
            return new SecretKey(this, value); 
        }
    }

}
