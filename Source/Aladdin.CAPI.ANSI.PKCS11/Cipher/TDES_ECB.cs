using System;
using Aladdin.PKCS11; 

namespace Aladdin.CAPI.ANSI.PKCS11.Cipher
{
	///////////////////////////////////////////////////////////////////////////////
	// Алгоритм шифрования TDES в режиме ECB
	///////////////////////////////////////////////////////////////////////////////
	public class TDES_ECB : CAPI.PKCS11.BlockMode
	{
        // размеры ключей
        private int[] keySizes; 

		// конструктор
		public TDES_ECB(CAPI.PKCS11.Applet applet, int[] keySizes)

			// сохранить переданные параметры
			: base(applet, PaddingMode.None) { this.keySizes = keySizes; } 

		// параметры алгоритма
		public override Mechanism GetParameters(CAPI.PKCS11.Session sesssion)
		{
			// параметры алгоритма
			return new Mechanism(API.CKM_DES3_ECB); 
		}
        // тип ключей
        public override SecretKeyFactory KeyFactory { get { return Keys.TDES.Instance; }}
		// размер ключа в байтах
		public override int[] KeySizes { get { return keySizes; }}
		// размер блока
		public override int BlockSize { get { return 8; }} 

		// режим алгоритма
		public override CipherMode Mode { get { return new CipherMode.ECB(); }}
	} 
}
