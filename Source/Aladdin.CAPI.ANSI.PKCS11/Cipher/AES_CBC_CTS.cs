using System;
using Aladdin.PKCS11; 

namespace Aladdin.CAPI.ANSI.PKCS11.Cipher
{
	///////////////////////////////////////////////////////////////////////////////
	// Алгоритм шифрования AES в режиме CBC с дополнением CTS
	///////////////////////////////////////////////////////////////////////////////
	public class AES_CBC_CTS : CAPI.PKCS11.BlockMode
	{
        // размеры ключей и параметры алгоритма
        private int[] keySizes; private CipherMode.CBC parameters;

		// конструктор
		public AES_CBC_CTS(CAPI.PKCS11.Applet applet, int[] keySizes, CipherMode.CBC parameters)

			// сохранить переданные параметры
			: base(applet, PaddingMode.CTS) 
		{
            // проверить размер блока
            if (parameters.BlockSize != 16) throw new NotSupportedException(); 

            // указать допустимые размеры ключей
            this.parameters = parameters; if (keySizes != null) this.keySizes = keySizes; 
            else {
                // получить информацию алгоритма
                MechanismInfo info = applet.GetAlgorithmInfo(API.CKM_AES_CTS); 
            
                // указать допустимые размеры ключей
                this.keySizes = CAPI.KeySizes.Range(info.MinKeySize, info.MaxKeySize, 8); 
            }
		} 
		// параметры алгоритма
		public override Mechanism GetParameters(CAPI.PKCS11.Session sesssion)
		{
			// вернуть параметры алгоритма
		    return new Mechanism(API.CKM_AES_CTS, parameters.IV); 
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
