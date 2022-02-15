using System; 

namespace Aladdin.CAPI.PBE
{
	///////////////////////////////////////////////////////////////////////////
	// Алгоритм вычисления имитовставки по паролю PBMAC1
	///////////////////////////////////////////////////////////////////////////
    public class PBMAC1 : Mac
	{
		private KeyDerive derivationAlgorithm;  // алгоритм наследования
		private Mac       macAlgorithm;		    // алгоритм вычисления имитовставки

		// конструктор 
		public PBMAC1(KeyDerive derivationAlgorithm, Mac macAlgorithm)
		{
            // сохранить переданные параметры
			this.derivationAlgorithm = RefObject.AddRef(derivationAlgorithm);
			this.macAlgorithm		 = RefObject.AddRef(macAlgorithm);
        }
        // освободить выделенные ресурсы
        protected override void OnDispose()
        {
            // освободить выделенные ресурсы
            RefObject.Release(derivationAlgorithm); 
                
            // освободить выделенные ресурсы
            RefObject.Release(macAlgorithm); base.OnDispose();
        }
		// размер MAC-значения в байтах
		public override int MacSize { get { return macAlgorithm.MacSize; } } 

		// размер блока в байтах
		public override int BlockSize { get { return macAlgorithm.BlockSize; } } 

		// инициализировать алгоритм
		public override void Init(ISecretKey password)
		{
            // определить тип ключа
            SecretKeyFactory keyFactory = macAlgorithm.KeyFactory; int keySize = -1; 

            // определить допустимые размеры ключей
            int[] keySizes = macAlgorithm.KeySizes; 
        
            // указать рекомендуемый размер ключа
            if (keySizes != null && keySizes.Length == 1) keySize = keySizes[0]; 

			// наследовать ключ по паролю
			using (ISecretKey key = derivationAlgorithm.DeriveKey(password, null, keyFactory, keySize))
            { 
                // проверить допустимость размера ключа
                if (!CAPI.KeySizes.Contains(keySizes, key.Length)) 
                {
                    // выбросить исключение
                    throw new InvalidOperationException();
                }
			    // инииализировать алгоритм
			    macAlgorithm.Init(key); 
            }
		}
		// захэшировать данные
		public override void Update(byte[] data, int dataOff, int dataLen)
		{
			// захэшировать данные
			macAlgorithm.Update(data, dataOff, dataLen); 
		}
		// получить MAC-значение
		public override int Finish(byte[] buf, int bufOff)
		{
			// получить MAC-значение
			return macAlgorithm.Finish(buf, bufOff); 
		}
	}
}
