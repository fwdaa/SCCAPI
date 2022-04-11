using System; 

namespace Aladdin.CAPI.ANSI.Keys
{
    ///////////////////////////////////////////////////////////////////////////
    // Ключ DESX
    ///////////////////////////////////////////////////////////////////////////
    public class DESX : SecretKeyFactory
    {
        // тип ключа
        public static readonly SecretKeyFactory Instance = new DESX(); 

        // конструктор
        public DESX() : base(new int[] {24}) {}

        // создать ключ
        public override ISecretKey Create(byte[] value) 
        { 
            // создать копию значения
            value = (byte[])value.Clone(); 
        
            // выполнить нормализацию ключа
            DES.AdjustParity(value, 0, 8); 
        
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
            DES.AdjustParity(value, 0, 8); 

            // вернуть сгенерированный ключ
            return new SecretKey(this, value); 
        }
    }
}
