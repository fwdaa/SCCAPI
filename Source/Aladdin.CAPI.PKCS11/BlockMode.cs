using System;

namespace Aladdin.CAPI.PKCS11
{
	///////////////////////////////////////////////////////////////////////////////
	// Режим блочного алгоритма шифрования
	///////////////////////////////////////////////////////////////////////////////
	public abstract class BlockMode : Cipher
	{
		// конструктор
		protected BlockMode(Applet applet, PaddingMode padding) : base(applet)
		 
			// сохранить переданные параметры
			{ this.padding = padding; } private PaddingMode padding;

		// алгоритм зашифрования данных
		public override Transform CreateEncryption(ISecretKey key, PaddingMode padding)
		{
			// указать режим дополнения
			if (this.padding != PaddingMode.Any) padding = this.padding; 
        
			// сохранить способ дополнения
			PaddingMode oldPadding = this.padding; this.padding = padding; 

			// указать режим дополнения
			BlockPadding paddingMode = GetPadding(); 
			try {
				// получить режим зашифрования 
				using (Transform encryption = CreateEncryption(key))
                {
				    // указать требуемое дополнение
				    return paddingMode.CreateEncryption(encryption, Mode); 
                }
			}
			// восстановить способ дополнения
			finally { this.padding = oldPadding; }
		}
		// алгоритм расшифрования данных
		public override Transform CreateDecryption(ISecretKey key, PaddingMode padding) 
		{
			// указать режим дополнения
			if (this.padding != PaddingMode.Any) padding = this.padding; 
        
			// сохранить способ дополнения
			PaddingMode oldPadding = this.padding; this.padding = padding; 

			// указать режим дополнения
			BlockPadding paddingMode = GetPadding(); 
			try {
				// получить режим расшифрования 
				using (Transform decryption = CreateDecryption(key))
                {
				    // указать требуемое дополнение
				    return paddingMode.CreateDecryption(decryption, Mode); 
                }
			}
			// восстановить способ дополнения
			finally { this.padding = oldPadding; }
		}
		// алгоритм зашифрования данных
		protected override Transform CreateEncryption(ISecretKey key) 
		{
			// создать алгоритм зашифрования данных
			return new Encryption(this, padding, key); 
		}
		// алгоритм расшифрования данных
		protected override Transform CreateDecryption(ISecretKey key)
		{
			// создать алгоритм расшифрования данных
			return new Decryption(this, padding, key); 
		}
        // указать режим дополнения
		protected virtual BlockPadding GetPadding() 
	    {
			// вернуть отсутствие дополнения
			if (padding == PaddingMode.None) return new Pad.None();

            // вернуть дополнение нулями
            if (padding == PaddingMode.Zero) return new Pad.Zero();

            // вернуть дополнение PKCS
            if (padding == PaddingMode.PKCS5) return new Pad.PKCS5(); 

            // вернуть дополнение ISO
            if (padding == PaddingMode.ISO) return new Pad.ISO(); 

            // для режима дополнения CTS
            if (padding == PaddingMode.CTS) return new Pad.CTS(); 

            // при ошибке выбросить исключение
            throw new NotSupportedException();
        }
	}
}
