﻿using System;
using Aladdin.PKCS11; 

namespace Aladdin.CAPI.ANSI.PKCS11.Cipher
{
	///////////////////////////////////////////////////////////////////////////////
	// Алгоритм шифрования RC5 в режиме CBC с дополнением PKCS5
	///////////////////////////////////////////////////////////////////////////////
	public class RC5_CBC_PAD : CAPI.PKCS11.BlockMode
	{
		// размер ключей, число раундов и параметры режима
		private int[] keySizes; private int rounds; private CipherMode.CBC parameters; 

		// конструктор
		public RC5_CBC_PAD(CAPI.PKCS11.Applet applet, int rounds, 
			
			// сохранить переданные параметры
			int[] keySizes, CipherMode.CBC parameters) : base(applet, PaddingMode.PKCS5)
		{ 
			// сохранить переданные параметры
			this.parameters = parameters; this.rounds = rounds; 

            // указать допустимые размеры ключей
            if (keySizes != null) this.keySizes = keySizes; 
            else {
                // получить информацию алгоритма
                MechanismInfo info = applet.GetAlgorithmInfo(API.CKM_RC5_CBC_PAD); 
            
                // указать допустимые размеры ключей
                this.keySizes = CAPI.KeySizes.Range(info.MinKeySize, info.MaxKeySize); 
            }
		}
		// параметры алгоритма
		public override Mechanism GetParameters(CAPI.PKCS11.Session sesssion)
		{
            // указать параметры алгоритма
            Parameters.CK_RC5_CBC_PARAMS rc5Parameters = 
                new Parameters.CK_RC5_CBC_PARAMS(
                    parameters.BlockSize / 2, rounds, parameters.IV
            ); 
		    // вернуть параметры алгоритма
		    return new Mechanism(API.CKM_RC5_CBC_PAD, rc5Parameters); 
		}
        // тип ключей
        public override SecretKeyFactory KeyFactory { get { return Keys.RC5.Instance; }}
		// размер ключа в байтах
		public override int[] KeySizes { get { return keySizes; }}
		// размер блока
		public override int BlockSize { get { return parameters.BlockSize; }} 

		// режим алгоритма
		public override CipherMode Mode { get { return parameters; }}
	} 
}