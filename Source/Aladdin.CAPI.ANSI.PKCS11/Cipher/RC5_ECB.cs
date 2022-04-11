using System;
using Aladdin.PKCS11; 

namespace Aladdin.CAPI.ANSI.PKCS11.Cipher
{
	///////////////////////////////////////////////////////////////////////////////
	// Алгоритм шифрования RC5 в режиме ECB
	///////////////////////////////////////////////////////////////////////////////
	public class RC5_ECB : CAPI.PKCS11.BlockMode
	{
		// размер ключей, размер блока и число раундов
		private int[] keySizes; private int blockSize; private int rounds; 

		// конструктор
		public RC5_ECB(CAPI.PKCS11.Applet applet, int blockSize, int rounds, 
			
			// сохранить переданные параметры
			 int[] keySizes) : base(applet, PaddingMode.None) 
		{ 
			// сохранить переданные параметры
			this.blockSize = blockSize; this.rounds = rounds;
 
            // указать допустимые размеры ключей
            if (keySizes != null) this.keySizes = keySizes; 
            else {
                // получить информацию алгоритма
                MechanismInfo info = applet.GetAlgorithmInfo(API.CKM_RC5_ECB); 
            
                // указать допустимые размеры ключей
                this.keySizes = CAPI.KeySizes.Range(info.MinKeySize, info.MaxKeySize); 
            }
		}
		// параметры алгоритма
		public override Mechanism GetParameters(CAPI.PKCS11.Session sesssion)
		{
            // указать параметры алгоритма
            Parameters.CK_RC5_PARAMS parameters = 
                new Parameters.CK_RC5_PARAMS(blockSize / 2, rounds); 

		    // вернуть параметры алгоритма
		    return new Mechanism(API.CKM_RC5_ECB, parameters); 
		}
        // тип ключей
        public override SecretKeyFactory KeyFactory 
		{ 
			// тип ключей
			get { return new Keys.RC5(keySizes); }
		}
		// размер блока
		public override int BlockSize { get { return blockSize; }} 

		// режим алгоритма
		public override CipherMode Mode { get { return new CipherMode.ECB(); }}
	} 
}
