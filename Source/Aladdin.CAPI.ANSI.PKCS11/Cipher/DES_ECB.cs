using System;
using Aladdin.PKCS11; 

namespace Aladdin.CAPI.ANSI.PKCS11.Cipher
{
	///////////////////////////////////////////////////////////////////////////////
	// Алгоритм шифрования DES в режиме ECB
	///////////////////////////////////////////////////////////////////////////////
	public class DES_ECB : CAPI.PKCS11.BlockMode
	{
		// конструктор
		public DES_ECB(CAPI.PKCS11.Applet applet) : base(applet, PaddingMode.None) {}

		// параметры алгоритма
		public override Mechanism GetParameters(CAPI.PKCS11.Session sesssion)
		{
			// параметры алгоритма
			return new Mechanism(API.CKM_DES_ECB); 
		}
        // тип ключей
        public override SecretKeyFactory KeyFactory { get { return Keys.DES.Instance; }}
		// размер ключа в байтах
		public override int[] KeySizes { get { return new int[] {8}; }}
		// размер блока
		public override int BlockSize { get { return 8; }} 

		// режим алгоритма
		public override CipherMode Mode { get { return new CipherMode.ECB(); }}
	} 
}
