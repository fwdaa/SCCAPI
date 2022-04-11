using System;
using Aladdin.PKCS11; 

namespace Aladdin.CAPI.ANSI.PKCS11.Cipher
{
	///////////////////////////////////////////////////////////////////////////////
	// Алгоритм шифрования TDES в режиме CBC
	///////////////////////////////////////////////////////////////////////////////
	public class TDES_CBC : CAPI.PKCS11.BlockMode
	{
        // размеры ключей и параметры алгоритма
        private int[] keySizes; private CipherMode.CBC parameters;

		// конструктор
		public TDES_CBC(CAPI.PKCS11.Applet applet, int[] keySizes, CipherMode.CBC parameters)

			// сохранить переданные параметры
			: base(applet, PaddingMode.None) 
		{
            // проверить размер блока
            if (parameters.BlockSize != 8) throw new NotSupportedException(); 

			// указать параметры алгоритма
			this.keySizes = keySizes; this.parameters = parameters; 
		} 
		// параметры алгоритма
		public override Mechanism GetParameters(CAPI.PKCS11.Session sesssion)
		{
			// вернуть параметры алгоритма
		    return new Mechanism(API.CKM_DES3_CBC, parameters.IV); 
		}
        // тип ключей
        public override SecretKeyFactory KeyFactory 
		{ 
			// тип ключей
			get { return new Keys.TDES(keySizes); }
		}
		// размер блока
		public override int BlockSize { get { return 8; }} 

		// режим алгоритма
		public override CipherMode Mode { get { return parameters; }}
	} 
}
