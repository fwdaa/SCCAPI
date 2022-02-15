namespace Aladdin.CAPI
{
    ///////////////////////////////////////////////////////////////////////////
	// Алгоритм псевдослучайной генерации
    ///////////////////////////////////////////////////////////////////////////
    public abstract class PRF : KeyDerive
    {
		// выполнить генерацию / наследовать ключ
		public override ISecretKey DeriveKey(ISecretKey key, 
            byte[] random, SecretKeyFactory keyFactory, int deriveSize)
        {
            // проверить тип ключа
            if (key.Value == null) throw new InvalidKeyException(); 

            // выделить буфер требуемого размера
            byte[] buffer = new byte[deriveSize]; 

		    // выполнить генерацию данных
		    Generate(key.Value, random, buffer, 0, deriveSize); 

            // создать ключ
            return keyFactory.Create(buffer); 
        }
		// выполнить генерацию данных
		public abstract void Generate(byte[] key, byte[] seed, 
            byte[] buffer, int offset, int deriveSize
        );
    }
}
