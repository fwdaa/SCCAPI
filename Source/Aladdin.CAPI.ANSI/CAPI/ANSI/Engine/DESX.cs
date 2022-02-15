using System;

namespace Aladdin.CAPI.ANSI.Engine
{
    ///////////////////////////////////////////////////////////////////////////
    // Алгоритм шифрования DES-X
    ///////////////////////////////////////////////////////////////////////////
    public class DESX : CAPI.Cipher
    {
		// конструктор
		public DESX(CAPI.Cipher des) 
        
            // сохранить переданные параметры
            { this.des = RefObject.AddRef(des); } private CAPI.Cipher des;
        
		// конструктор
		public DESX() { this.des = new Engine.DES(); } 
        
        // освободить ресурсы 
        protected override void OnDispose() 
        {
            // освободить ресурсы 
            RefObject.Release(des); base.OnDispose(); 
        }
        // тип ключа
        public override SecretKeyFactory KeyFactory { get { return Keys.DESX.Instance; }}
        // размер блока
		public override int BlockSize { get { return des.BlockSize; }}

		// алгоритм зашифрования блока данных
		protected override Transform CreateEncryption(ISecretKey key) 
		{
            // проверить тип ключа
            byte[] value = key.Value; if (value == null) 
            {
                // при ошибке выбросить исключение
                throw new InvalidKeyException();
            }
            // проверить размер ключа
            if (value.Length != 24) throw new InvalidKeyException(); 

            // вернуть алгоритм зашифрования блока данных
		    return new Encryption(des, key); 
		}
		// алгоритм расшифрования блока данных
		protected override Transform CreateDecryption(ISecretKey key)
		{
            // проверить тип ключа
            byte[] value = key.Value; if (value == null) 
            {
                // при ошибке выбросить исключение
                throw new InvalidKeyException();
            }
            // проверить размер ключа
            if (value.Length != 24) throw new InvalidKeyException(); 

		    // вернуть алгоритм расшифрования блока данных
		    return new Decryption(des, key);
		}
	    ///////////////////////////////////////////////////////////////////////////
	    // Алгоритм зашифрования блока
	    ///////////////////////////////////////////////////////////////////////////
	    public class Encryption : BlockTransform
	    {
		    // используемое преобразование и дополнительные ключи
		    private Transform transform; private byte[] K1; private byte[] K2;
       
		    // Конструктор
		    public Encryption(CAPI.Cipher des, ISecretKey key) : base(8)
		    { 
			    // проверить тип ключа
			   byte[] value = key.Value; if (value == null) throw new InvalidKeyException();

                // извлечь значения ключей
                K1 = Arrays.CopyOf(value, 8, 8); K2 = Arrays.CopyOf(value, 16, 8);
            
                // указать используемый ключ
                using (ISecretKey K = des.KeyFactory.Create(Arrays.CopyOf(value, 0, 8)))
                { 
                    // указать используемое преобразование
                    transform = des.CreateEncryption(K, PaddingMode.None); 
                }
		    }
            // освободить ресурсы 
            protected override void OnDispose() 
            {
                // освободить ресурсы 
                RefObject.Release(transform); base.OnDispose();
            }
		    // обработка одного блока данных
		    protected override void Update(byte[] src, int srcOff, byte[] dest, int destOff)
		    {
                // скопировать данные
                Array.Copy(src, srcOff, dest, destOff, 8);
            
                // выполнить сложение с ключом
                for (int i = 0; i < 8; i++) dest[destOff + i] ^= K1[i]; 
            
                // выполнить преобразование
                transform.Update(dest, destOff, 8, dest, destOff);

                // выполнить сложение с ключом
                for (int i = 0; i < 8; i++) dest[destOff + i] ^= K2[i]; 
            }
	    }
	    ///////////////////////////////////////////////////////////////////////////
	    // Алгоритм расшифрования блока
	    ///////////////////////////////////////////////////////////////////////////
	    public class Decryption : BlockTransform
	    {
		    // используемое преобразование и дополнительные ключи
		    private Transform transform; private byte[] K1; private byte[] K2;
       
		    // Конструктор
		    public Decryption(CAPI.Cipher des, ISecretKey key) : base(8)
		    { 
			    // проверить тип ключа
			    byte[] value = key.Value; if (value == null)
			    {
				    // при ошибке выбросить исключение
				    throw new InvalidKeyException();
			    }
                // извлечь значения ключей
                K1 = Arrays.CopyOf(value, 8, 8); K2 = Arrays.CopyOf(value, 16, 8);
            
                // указать используемый ключ
                using (ISecretKey K = des.KeyFactory.Create(Arrays.CopyOf(value, 0, 8)))
                { 
                    // указать используемое преобразование
                    transform = des.CreateDecryption(K, PaddingMode.None); 
                }
		    }
            // освободить ресурсы 
            protected override void OnDispose()
            {
                // освободить ресурсы 
                RefObject.Release(transform); base.OnDispose();
            }
		    // обработка одного блока данных
		    protected override void Update(byte[] src, int srcOff, byte[] dest, int destOff)
		    {
                // скопировать данные
                Array.Copy(src, srcOff, dest, destOff, 8);
            
                // выполнить сложение с ключом
                for (int i = 0; i < 8; i++) dest[destOff + i] ^= K2[i]; 
            
                // выполнить преобразование
                transform.Update(dest, destOff, 8, dest, destOff);

                // выполнить сложение с ключом
                for (int i = 0; i < 8; i++) dest[destOff + i] ^= K1[i]; 
		    }
	    }
    }
}
