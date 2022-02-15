using System; 

///////////////////////////////////////////////////////////////////////////
// Алгоритм диверсификации ключа
///////////////////////////////////////////////////////////////////////////
namespace Aladdin.CAPI.GOST.Derive
{
    public class RFC4357 : KeyDerive
    {
        // способ кодирования чисел
        private const Math.Endian Endian = Math.Endian.LittleEndian; 

        // блочный алгоритм шифрования
        private IBlockCipher gost28147;
    
	    // конструктор
	    public RFC4357(IBlockCipher gost28147)
        {  
		    // сохранить переданные параметры
		    this.gost28147 = RefObject.AddRef(gost28147); 
        }  
        // освободить ресурсы
        protected override void OnDispose() 
        { 
            // освободить ресурсы
            RefObject.Release(gost28147); base.OnDispose();
        }
        // тип ключа
        public override SecretKeyFactory KeyFactory { get { return gost28147.KeyFactory; }} 
        // размер используемых ключей
        public override int[] KeySizes { get { return gost28147.KeySizes; }}

	    // наследовать ключ
	    public override ISecretKey DeriveKey(ISecretKey key, 
            byte[] ukm, SecretKeyFactory keyFactory, int deriveSize) 
	    {
            // указать размер генерируемого ключа
            if (deriveSize < 0) deriveSize = 32; 
        
		    // проверить размер генерируемого ключа
		    if (deriveSize != 32) throw new NotSupportedException();
 
            // проверить корректность параметров
            if (ukm.Length != 8) throw new ArgumentException(); 

		    // скопировать значение ключа
		    byte[] value = (byte[])key.Value.Clone(); 

            // выполнить 8 раз
		    for (int i = 0; i < 8; i++)
		    {
			    // инициализировать синхропосылку
			    uint[] s = new uint[2]; int mask = 1; byte[] iv = new byte[8]; 

			    // вычислить синхропосылку
			    for (int j = 0; j < 8; j++, mask <<= 1)
			    {
				    // извлечь часть ключа 
				    uint partKey = Math.Convert.ToUInt32(value, j * 4, Endian); 
                
				    // изменить часть синхропосылки
				    s[((mask & ukm[i]) != 0) ? 0 : 1] += partKey;
			    }
			    // переустановить синхропосылку
                Math.Convert.FromUInt32(s[0], Endian, iv, 0); 
                Math.Convert.FromUInt32(s[1], Endian, iv, 4); 
            
                // создать ключ шифрования ключа
                using (ISecretKey KEK = key.KeyFactory.Create(value))
                {
                    // указать параметры шифрования
                    CipherMode.CFB parameters = new CipherMode.CFB(iv, gost28147.BlockSize); 

			        // создать преобразование зашифрования
                    using (CAPI.Cipher modeCFB = gost28147.CreateBlockMode(parameters))
                    { 
			            // зашифровать ключ
			            modeCFB.Encrypt(KEK, PaddingMode.None, value, 0, value.Length, value, 0);
                    } 
                }
		    }
            // вернуть созданный ключ
            return keyFactory.Create(value);
        }
    }
}