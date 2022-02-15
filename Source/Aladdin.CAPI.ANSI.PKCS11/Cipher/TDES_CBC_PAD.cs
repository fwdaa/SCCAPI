using System;
using Aladdin.PKCS11; 

namespace Aladdin.CAPI.ANSI.PKCS11.Cipher
{
	///////////////////////////////////////////////////////////////////////////////
	// Алгоритм шифрования TDES в режиме CBC с дополнением PKCS5
	///////////////////////////////////////////////////////////////////////////////
	public class TDES_CBC_PAD : CAPI.PKCS11.BlockMode
	{
        // размеры ключей и параметры алгоритма
        private int[] keySizes; private CipherMode.CBC parameters;

		// конструктор
		public TDES_CBC_PAD(CAPI.PKCS11.Applet applet, int[] keySizes, CipherMode.CBC parameters)

			// сохранить переданные параметры
			: base(applet, PaddingMode.PKCS5) 
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
		    return new Mechanism(API.CKM_DES3_CBC_PAD, parameters.IV); 
		}
        // тип ключей
        public override SecretKeyFactory KeyFactory { get { return Keys.TDES.Instance; }}
		// размер ключа в байтах
		public override int[] KeySizes { get { return keySizes; }}
		// размер блока
		public override int BlockSize { get { return 8; }} 

		// режим алгоритма
		public override CipherMode Mode { get { return parameters; }}
	} 
}
