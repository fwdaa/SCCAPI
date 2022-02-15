namespace Aladdin.CAPI.PBE
{
    ///////////////////////////////////////////////////////////////////////////
    // Алгоритм вычисления имитовставки по паролю PBMAC PKCS12 TK26
    ///////////////////////////////////////////////////////////////////////////
    public class PBMACTC26 : Mac
    {
	    // алгоритм вычисления имитовставки и наследования ключа
	    private Mac macAlgorithm; private KeyDerive derivationAlgorithm; 
    
	    // конструктор
	    public PBMACTC26(Hash hashAlgorithm, byte[] salt, int iterations)
	    {
		    // создать алгоритм вычисления имитовставки
		    macAlgorithm = new MAC.HMAC(hashAlgorithm);  

            // создать алгоритм наследования ключа
            derivationAlgorithm = new PBKDF2(macAlgorithm, salt, iterations, -1); 
	    }
        // освободить выделенные ресурсы
        protected override void OnDispose()
        {
            // освободить выделенные ресурсы
            macAlgorithm.Dispose(); derivationAlgorithm.Dispose(); base.OnDispose();
        }
	    // размер MAC-значения в байтах
	    public override int MacSize { get { return macAlgorithm.MacSize; }} 

		// размер блока в байтах
		public override int BlockSize { get { return macAlgorithm.BlockSize; } } 

	    // инициализировать алгоритм
	    public override void Init(ISecretKey password) 
	    {
		    // определить размер ключа
		    SecretKeyFactory keyFactory = SecretKeyFactory.Generic; int keySize = macAlgorithm.MacSize; 

            // сгенерировать случайные данные
            using (ISecretKey key = derivationAlgorithm.DeriveKey(password, null, keyFactory, 96))
            { 
                // извлечь последние байты
                byte[] value = Arrays.CopyOf(key.Value, 64, 32); 
        
                // инициализировать алгоритм вычисления имитовставки
                using (ISecretKey k = macAlgorithm.KeyFactory.Create(value)) macAlgorithm.Init(k);
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