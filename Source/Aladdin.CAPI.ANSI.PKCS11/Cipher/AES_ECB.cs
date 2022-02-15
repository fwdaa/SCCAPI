using System;
using Aladdin.PKCS11; 

namespace Aladdin.CAPI.ANSI.PKCS11.Cipher
{
	///////////////////////////////////////////////////////////////////////////////
	// Алгоритм шифрования AES в режиме ECB
	///////////////////////////////////////////////////////////////////////////////
	public class AES_ECB : CAPI.PKCS11.BlockMode
	{
        // размеры ключей
        private int[] keySizes; 

		// конструктор
		public AES_ECB(CAPI.PKCS11.Applet applet, int[] keySizes)

			// сохранить переданные параметры
			: base(applet, PaddingMode.None) 
        { 
            // указать допустимые размеры ключей
            if (keySizes != null) this.keySizes = keySizes; 
            else {
                // получить информацию алгоритма
                MechanismInfo info = applet.GetAlgorithmInfo(API.CKM_AES_ECB); 
            
                // указать допустимые размеры ключей
                this.keySizes = CAPI.KeySizes.Range(info.MinKeySize, info.MaxKeySize, 8); 
            }
        }
		// параметры алгоритма
		public override Mechanism GetParameters(CAPI.PKCS11.Session sesssion)
		{
			// параметры алгоритма
			return new Mechanism(API.CKM_AES_ECB); 
		}
        // тип ключей
        public override SecretKeyFactory KeyFactory { get { return Keys.AES.Instance; }}
		// размер ключа в байтах
		public override int[] KeySizes { get { return keySizes; }}
		// размер блока
		public override int BlockSize { get { return 16; }} 

		// режим алгоритма
		public override CipherMode Mode { get { return new CipherMode.ECB(); }}
	} 
}
