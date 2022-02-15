using System.Text; 

namespace Aladdin.CAPI
{
	///////////////////////////////////////////////////////////////////////////
	// Ключ симметричного алгоритма
	///////////////////////////////////////////////////////////////////////////
	public sealed class SecretKey : ISecretKey 
	{
	    // конструктор
	    public static ISecretKey FromPassword(string password, Encoding encoding) 
        { 
            // закодировать пароль
            byte[] encoded = encoding.GetBytes(password); 
        
            // создать объект ключа 
            return new SecretKey(SecretKeyFactory.Generic, encoded); 
        } 
        // тип и значение ключа
        private SecretKeyFactory type; private byte[] value; 

        // конструктор
        public SecretKey(SecretKeyFactory type, byte[] value) 
        {     
            // сохранить переданные параметры
            this.type = type; this.value = value; 
        } 
        // тип ключа
        public SecretKeyFactory KeyFactory { get { return type; }}
        // размер ключа
        public int Length { get { return value.Length; }}
        // значение ключа
        public byte[] Value { get { return value; }}

        // увеличить/уменьшить счетчик ссылок
        public void AddRef () {} 
        public void Release() {} 
    
        // уменьшить счетчик ссылок
        public void Dispose() { Release(); }

        ///////////////////////////////////////////////////////////////////////
        // Нормализация ключа DES
        ///////////////////////////////////////////////////////////////////////
        private static void DesAdjustKeyParity(byte[] key, int offset, int length)
        {
            // для всех байтов ключа
            for (int i = 0; i < length; i++)
            {
                // для вех битов
                int ones = 0; for (int j = 0; j < 8; j++)
                {
                    // определить число установленных битов
                    if ((key[offset + i] & (0x1 << j)) != 0) ones++;
                }
                // число установленных битов должно быть нечетным
                if ((ones % 2) == 0) key[offset + i] ^= 0x01;
            }
        } 
	}
}
