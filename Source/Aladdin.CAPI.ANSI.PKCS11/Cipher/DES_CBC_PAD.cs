using System;
using Aladdin.PKCS11; 

namespace Aladdin.CAPI.ANSI.PKCS11.Cipher
{
	///////////////////////////////////////////////////////////////////////////////
	// Алгоритм шифрования DES в режиме CBC с дополнением PKCS5
	///////////////////////////////////////////////////////////////////////////////
	public class DES_CBC_PAD : CAPI.PKCS11.BlockMode
	{
		// параметры алгоритма
		private CipherMode.CBC parameters;  

		// конструктор
		public DES_CBC_PAD(CAPI.PKCS11.Applet applet, CipherMode.CBC parameters)

			// сохранить переданные параметры
			: base(applet, PaddingMode.PKCS5) { this.parameters = parameters; 

            // проверить размер блока
            if (parameters.BlockSize != 8) throw new NotSupportedException(); 
        }
		// параметры алгоритма
		public override Mechanism GetParameters(CAPI.PKCS11.Session sesssion)
		{
			// вернуть параметры алгоритма
		    return new Mechanism(API.CKM_DES_CBC_PAD, parameters.IV); 
		}
        // тип ключей
        public override SecretKeyFactory KeyFactory { get { return Keys.DES.Instance; }}
		// размер ключа в байтах
		public override int[] KeySizes { get { return new int[] {8}; }}
		// размер блока
		public override int BlockSize { get { return 8; }} 

		// режим алгоритма
		public override CipherMode Mode { get { return parameters; }}
    } 
}
