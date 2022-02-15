using System;
using System.Text;

namespace Aladdin.CAPI.PBE
{
	///////////////////////////////////////////////////////////////////////////
	// Алгоритм вычисления имитовставки по паролю PKIX
	///////////////////////////////////////////////////////////////////////////
	public class PBMAC : Mac
	{
		private Hash	hashAlgorithm;	// алгоритм хэширования
		private Mac	    macAlgorithm;	// алгоритм вычисления имитовставки
      	private int		keySize;		// размер ключа алгоритма
		private byte[]	salt;			// salt-значение
		private int		iterations;		// число итераций

		// конструктор 
		public PBMAC(Hash hashAlgorithm, Mac macAlgorithm, byte[] salt, int iterations)
		{
            // получить допустимые размеры ключей
            int[] keySizes = macAlgorithm.KeySizes; 
        
            // проверить наличие ключей фиксированного размера
            if (keySizes == null || keySizes.Length != 1) 
            {
                // при ошибке выбросить исключение
                throw new InvalidOperationException();
            } 
            // сохранить переданные параметры
			this.hashAlgorithm	= RefObject.AddRef(hashAlgorithm);
			this.macAlgorithm	= RefObject.AddRef(macAlgorithm);

            // сохранить переданные параметры
            this.keySize = keySizes[0]; this.salt = salt; this.iterations = iterations;
	    }
        // освободить используемые ресурсы
        protected override void OnDispose() 
        {
            // освободить используемые ресурсы
            RefObject.Release(hashAlgorithm); 
                
            // освободить используемые ресурсы
            RefObject.Release(macAlgorithm); base.OnDispose();
        }
		// размер MAC-значения в байтах
		public override int MacSize { get { return macAlgorithm.MacSize; } } 

		// размер блока в байтах
		public override int BlockSize { get { return macAlgorithm.BlockSize; } } 

		// инициализировать алгоритм
		public override void Init(ISecretKey password)
		{
			// проверить тип ключа
			if (password.Value == null) throw new InvalidKeyException();

			// объединить пароль с salt-значением
			byte[] K = Arrays.Concat(password.Value, salt); 

			// захэшировать пароль и salt-значение
			K = hashAlgorithm.HashData(K, 0, K.Length); 
			
			// выполнить требуемое число итераций
			for (int i = 0; i < iterations; i++)
			{
				// захэшировать ключ
				K = hashAlgorithm.HashData(K, 0, K.Length); 
			}
			// выделить память для ключа
			byte[] key = new byte[keySize]; 

			// проверьть необходимость расширения ключа
			if (K.Length >= key.Length) Array.Copy(K, 0, key, 0, key.Length); 
			else {
				// скопировать ключ
				Array.Copy(K, 0, key, 0, K.Length); int ofs = K.Length; 

				// для всех полных блоков
				for (int i = 1; ofs < key.Length; ofs += K.Length, i++)
				{
					// закодировать номер
					byte[] number = Encoding.ASCII.GetBytes(i.ToString()); 

					// объединить номер с ключом
					byte[] data = Arrays.Concat(number, K); 

					// захэшировать ключ
					K = hashAlgorithm.HashData(data, 0, data.Length); 

					// скопировать ключ
					Array.Copy(K, 0, key, ofs, System.Math.Min(K.Length, key.Length - ofs));
				}
			}
			// инициализировать алгоритм
			using (ISecretKey k = macAlgorithm.KeyFactory.Create(key)) macAlgorithm.Init(k);
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
