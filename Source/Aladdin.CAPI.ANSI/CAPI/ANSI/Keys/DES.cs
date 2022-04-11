using System; 

namespace Aladdin.CAPI.ANSI.Keys
{
    ///////////////////////////////////////////////////////////////////////////
    // Ключ DES
    ///////////////////////////////////////////////////////////////////////////
    public class DES : SecretKeyFactory
    {
        // тип ключа
        public static readonly SecretKeyFactory Instance = new DES(); 

        // конструктор
        public DES() : base(new int[] {8}) {}

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
        ///////////////////////////////////////////////////////////////////////////
        // Нормализация ключа
        ///////////////////////////////////////////////////////////////////////////
        public static void AdjustParity(byte[] key, int offset, int length)
        {
            // для всех байтов ключа
            for (int i = 0; i < length; i++)
            {
                // для вех битов
                int ones = 0; for (int j = 0; j < 8; j++)
                {
                    // определить число установленных битов
                    if ((key[i + offset] & (0x1 << j)) != 0) ones++;
                }
                // число установленных битов должно быть нечетным
                if((ones % 2) == 0) key[i + offset] ^= 0x01;
            }
        } 
    }
}
