using System;
using Aladdin.PKCS11; 

namespace Aladdin.CAPI.ANSI.PKCS11.Cipher
{
	///////////////////////////////////////////////////////////////////////////////
	// Алгоритм шифрования RC2 в режиме ECB
	///////////////////////////////////////////////////////////////////////////////
	public class RC2_ECB : CAPI.PKCS11.BlockMode
	{
		// эффективное число битов ключа и размер ключей
		private int effectiveKeyBits; private int[] keySizes;  

		// конструктор
		public RC2_ECB(CAPI.PKCS11.Applet applet, int effectiveKeyBits, int[] keySizes)

			// сохранить переданные параметры
			 : base(applet, PaddingMode.None) { this.effectiveKeyBits = effectiveKeyBits; 

            // указать допустимые размеры ключей
            if (keySizes != null) this.keySizes = keySizes; 
            else {
                // получить информацию алгоритма
                MechanismInfo info = applet.GetAlgorithmInfo(API.CKM_RC2_ECB); 
            
                // указать допустимые размеры ключей
                this.keySizes = CAPI.KeySizes.Range((info.MinKeySize + 7) / 8, info.MaxKeySize / 8); 
            }
        } 
		// параметры алгоритма
		public override Mechanism GetParameters(CAPI.PKCS11.Session sesssion)
		{
			// вернуть параметры алгоритма
            return new Mechanism(API.CKM_RC2_ECB, effectiveKeyBits); 
		}
        // тип ключей
        public override SecretKeyFactory KeyFactory 
		{ 
			// тип ключей
			get { return new Keys.RC2(keySizes); }
		}
		// размер блока
		public override int BlockSize { get { return 8; }} 

		// режим алгоритма
		public override CipherMode Mode { get { return new CipherMode.ECB(); }}
	} 
}
