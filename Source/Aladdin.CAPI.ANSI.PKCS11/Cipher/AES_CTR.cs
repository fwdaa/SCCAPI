using System;
using Aladdin.PKCS11; 

namespace Aladdin.CAPI.ANSI.PKCS11.Cipher
{
	///////////////////////////////////////////////////////////////////////////////
	// Алгоритм шифрования AES в режиме CTR
	///////////////////////////////////////////////////////////////////////////////
	public class AES_CTR : CAPI.PKCS11.BlockMode
	{
        // размеры ключей и число битов счетчика
        private int[] keySizes; private int counterBits; 
        // параметры алгоритма
        private CipherMode.CTR parameters;

		// конструктор
		public AES_CTR(CAPI.PKCS11.Applet applet, int[] keySizes, byte[] iv, int counterBits)

			// сохранить переданные параметры
			: base(applet, PaddingMode.None) 
		{
			// сохранить переданные параметры
            this.parameters = new CipherMode.CTR(iv, 16); this.counterBits = counterBits; 
            
            // указать допустимые размеры ключей
            if (keySizes != null) this.keySizes = keySizes; 
            else {
                // получить информацию алгоритма
                MechanismInfo info = applet.GetAlgorithmInfo(API.CKM_AES_CTR); 
            
                // указать допустимые размеры ключей
                this.keySizes = CAPI.KeySizes.Range(info.MinKeySize, info.MaxKeySize, 8); 
            }
		} 
		// параметры алгоритма
		public override Mechanism GetParameters(CAPI.PKCS11.Session sesssion)
		{
            // указать параметры
            Parameters.CK_AES_CTR_PARAMS aesParameters = 
                new Parameters.CK_AES_CTR_PARAMS(parameters.IV, counterBits); 

			// вернуть параметры алгоритма
		    return new Mechanism(API.CKM_AES_CTR, aesParameters); 
		}
        // тип ключей
        public override SecretKeyFactory KeyFactory 
		{ 
			// тип ключей
			get { return new Keys.AES(keySizes); }
		}
		// размер блока
		public override int BlockSize { get { return 16; }} 

		// режим алгоритма
		public override CipherMode Mode { get { return parameters; }}
	} 
}
