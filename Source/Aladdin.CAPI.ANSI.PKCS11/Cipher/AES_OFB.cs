using System;
using Aladdin.PKCS11; 

namespace Aladdin.CAPI.ANSI.PKCS11.Cipher
{
	///////////////////////////////////////////////////////////////////////////////
	// Алгоритм шифрования AES в режиме OFB
	///////////////////////////////////////////////////////////////////////////////
	public class AES_OFB : CAPI.PKCS11.BlockMode
	{
        // размеры ключей и параметры алгоритма
        private int[] keySizes; private CipherMode.OFB parameters;

		// конструктор
		public AES_OFB(CAPI.PKCS11.Applet applet, int[] keySizes, CipherMode.OFB parameters)

			// сохранить переданные параметры
			: base(applet, PaddingMode.None) 
		{
            // проверить размер блока
            if (parameters.BlockSize != 16) throw new NotSupportedException(); 

            // указать допустимые размеры ключей
            this.parameters = parameters; if (keySizes != null) this.keySizes = keySizes; 
            else {
                // получить информацию алгоритма
                MechanismInfo info = applet.GetAlgorithmInfo(API.CKM_AES_OFB); 
            
                // указать допустимые размеры ключей
                this.keySizes = CAPI.KeySizes.Range(info.MinKeySize, info.MaxKeySize, 8); 
            }
		} 
		// параметры алгоритма
		public override Mechanism GetParameters(CAPI.PKCS11.Session sesssion)
		{
			// вернуть параметры алгоритма
		    return new Mechanism(API.CKM_AES_OFB, parameters.IV); 
		}
        // тип ключей
        public override SecretKeyFactory KeyFactory { get { return Keys.AES.Instance; }}
		// размер ключа в байтах
		public override int[] KeySizes { get { return keySizes; }}
		// размер блока
		public override int BlockSize { get { return 16; }} 

		// режим алгоритма
		public override CipherMode Mode { get { return parameters; }}
	} 
}
