using System;

namespace Aladdin.CAPI.MAC
{
	///////////////////////////////////////////////////////////////////////////////
	// Алгоритм вычисления имитовставки HMAC
	///////////////////////////////////////////////////////////////////////////////
	public class HMAC : Mac
	{
		// алгоритм хэширования, размер блока и ключ
		private Hash algorithm; private int blockSize; private byte[] key;

		// конструктор
		public HMAC(Hash algorithm)
		{ 
			// сохранить переданные параметры
            this.algorithm = RefObject.AddRef(algorithm); 
 
			// выделить память для ключа
            blockSize = algorithm.BlockSize; this.key = new byte[blockSize];
		}
        // освободить выделенные ресурсы
        protected override void OnDispose()
        {
            // освободить выделенные ресурсы
            RefObject.Release(algorithm); base.OnDispose();
        }
		// размер MAC-значения в байтах 
		public override int MacSize { get { return algorithm.HashSize; } }
	  
		// размер блока в байтах 
		public override int BlockSize { get { return algorithm.BlockSize; } }

		// инициализировать алгоритм
		public override void Init(ISecretKey key)
		{
		    // проверить тип ключа
		    if (key.Value == null) throw new InvalidKeyException();
        
            // получить значение ключа
            byte[] value = key.Value; if (value.Length > blockSize)
            {
			    // прохэшировать ключ
			    value = algorithm.HashData(value, 0, value.Length); 
            }
            // скопировать ключ
		    if (value.Length > blockSize) Array.Copy(value, 0, this.key, 0, blockSize);
            else {
                // скопировать ключ
                Array.Copy(value, 0, this.key, 0, value.Length);
            
                // обнулить неиспользуемые данных
                for (int i = value.Length; i < this.key.Length; i++) this.key[i] = 0; 
            } 
			// скопировать ключ для хэширования
			byte[] k_ipad = (byte[])this.key.Clone(); 

			// дополнить ключ
			for (int i = 0; i < blockSize; i++) k_ipad[i] ^= 0x36;

			// прохэшировать дополненный ключ
			algorithm.Init(); algorithm.Update(k_ipad, 0, blockSize);
		}
		// захэшировать данные
		public override void Update(byte[] data, int dataOff, int dataLen)
		{
			// прохэшировать данные
			algorithm.Update(data, dataOff, dataLen);
		}
		// получить MAC-значение
		public override int Finish(byte[] buf, int bufOff)
		{
			// выделить буфер для хэш-значения
			byte[] hash = new byte[algorithm.HashSize]; 

			// вычислить хэш-значение
			int cbHash = algorithm.Finish(hash, 0); 

			// выделить память для завершающего хэширования
			byte[] k_opad = new byte[blockSize + cbHash];
 
			// скопировать ключ и хэш-значение
			Array.Copy(key,  0, k_opad,      0, blockSize); 
			Array.Copy(hash, 0, k_opad, blockSize, cbHash); 
			
			// дополнить ключ
			for (int i = 0; i < blockSize; i++) k_opad[i] ^= 0x5C;

			// выполнить завершающее хэширование
			hash = algorithm.HashData(k_opad, 0, k_opad.Length);

			// скопировать хэш-значение
			Array.Copy(hash, 0, buf, bufOff, hash.Length); return hash.Length; 
		}
	}
}
