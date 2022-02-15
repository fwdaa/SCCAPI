namespace Aladdin.CAPI.PBE
{
	///////////////////////////////////////////////////////////////////////////
	// Алгоритм вычисления имитовставки по паролю MACPKCS12
	///////////////////////////////////////////////////////////////////////////
    public class PBMACP12 : Mac
	{
		// алгоритм вычисления имитовставки и наследования ключа
		private Mac macAlgorithm; private KeyDerive derivationAlgorithm;

		// конструктор
		public PBMACP12(Hash hashAlgorithm, byte[] salt, int iterations)
		{
			// создать алгоритм вычисления имитовставки
			macAlgorithm = new MAC.HMAC(hashAlgorithm);
 
			// создать алгоритм наследования ключа
			derivationAlgorithm = new PBKDFP12(hashAlgorithm, salt, iterations, 3); 
		}
        // освободить выделенные ресурсы
        protected override void OnDispose()
        {
            // освободить выделенные ресурсы
            macAlgorithm.Dispose(); derivationAlgorithm.Dispose(); base.OnDispose();
        }
		// размер MAC-значения в байтах
		public override int MacSize { get { return macAlgorithm.MacSize; } } 

		// размер блока в байтах
		public override int BlockSize { get { return macAlgorithm.BlockSize; } } 

		// инициализировать алгоритм
		public override void Init(ISecretKey password)
		{
			// определить тип и размер ключа
			SecretKeyFactory keyFactory = macAlgorithm.KeyFactory; 

			// наследовать ключ по паролю
            using (ISecretKey key = derivationAlgorithm.DeriveKey(
                password, null, keyFactory, macAlgorithm.MacSize))
            {
                // инициализировать алгоритм
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
