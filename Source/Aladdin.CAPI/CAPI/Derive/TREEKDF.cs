using System;

namespace Aladdin.CAPI.Derive
{
    ///////////////////////////////////////////////////////////////////////////
    // Схема диверсификации KDF_TREE
    ///////////////////////////////////////////////////////////////////////////
    public class TREEKDF : KeyDerive
    {
        // алгоритм выработки МАС и размер MAC-значения
        private Mac algorithm; private int macSize; 

        // параметры алгоритма
        private byte[] label; private int R; 

        // конструктор
        public TREEKDF(Mac algorithm, byte[] label, int R)
        {
            // проверить корректность параметров
            if (R <= 0 || R > 4) throw new ArgumentException(); 

            // сохранить переданные параметры
            this.algorithm = RefObject.AddRef(algorithm); 

            // сохранить переданные параметры
            macSize = algorithm.MacSize; this.label = label; this.R = R; 
        }
        // освободить выделенные ресурсы
        protected override void OnDispose()
        {
            // освободить выделенные ресурсы
            RefObject.Release(algorithm); base.OnDispose();
        }
        // тип ключа
        public override SecretKeyFactory KeyFactory { get { return algorithm.KeyFactory; }} 
        // размер ключей
        public override int[] KeySizes { get { return algorithm.KeySizes; }}

        // сгенерировать блок данных
	    public override ISecretKey DeriveKey(ISecretKey key, 
            byte[] seed, SecretKeyFactory keyFactory, int deriveSize) 
        {
            // проверить наличие размера
            if (deriveSize < 0) throw new InvalidOperationException(); 

            // определить число итераций
            int iterations = (deriveSize + macSize - 1) / macSize; long l = deriveSize * 8; 

            // проверить корректность данных
            if (iterations > (1 << (R * 8)) - 1) throw new ArgumentException(); 

            // определить число байтов для L
            int L = (l <= 0xFF) ? 1 : ((l <= 0xFFFF) ? 2 : ((l <= 0xFFFFFF) ? 3 : 4));  

            // выделить буфер требуемого размера
            byte[] buffer = new byte[deriveSize]; int offset = 0;  
        
            // для всех блоков данных
            for (int i = 1; deriveSize > 0; offset += macSize, deriveSize -= macSize, i++)
            {
                // выделить буфер требуемого размера
                byte[] data = new byte[R + label.Length + 1 + seed.Length + L]; 

                // закодировать номер итерации
                for (int j = 0; j < R; j++) data[R - j - 1] = (byte)(i >> (8 * j));

                // скопировать label и seed
                Array.Copy(label, 0, data, R                   , label.Length); 
                Array.Copy(seed , 0, data, R + label.Length + 1, seed .Length); 

                // указать смещения числа битов
                int offsetL = R + label.Length + 1 + seed.Length;

                // закодировать число битов
                for (int j = 0; j < L; j++) data[offsetL + L - j - 1] = (byte)(l >> (8 * j));

                // выполнить хэширование данных
                byte[] mac = algorithm.MacData(key, data, 0, data.Length); 

                // скопировать хэш-значение
                Array.Copy(mac, 0, buffer, offset, (mac.Length < deriveSize) ? mac.Length : deriveSize); 
            } 
            // вернуть созданный ключ
            return keyFactory.Create(buffer); 
        } 
    }
}
