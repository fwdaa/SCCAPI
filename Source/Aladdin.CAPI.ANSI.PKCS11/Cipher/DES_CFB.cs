using System;
using Aladdin.PKCS11; 

namespace Aladdin.CAPI.ANSI.PKCS11.Cipher
{
	///////////////////////////////////////////////////////////////////////////////
	// Алгоритм шифрования DES в режиме CFB
	///////////////////////////////////////////////////////////////////////////////
	public class DES_CFB : CAPI.PKCS11.BlockMode
	{
		// идентификатор и параметры алгоритма
		private ulong algID; private CipherMode.CFB parameters;  

		// конструктор
		public DES_CFB(CAPI.PKCS11.Applet applet, CipherMode.CFB parameters)

			// сохранить переданные параметры
			: base(applet, PaddingMode.None) { this.parameters = parameters; 

            // в зависимости от размера блока
            switch (parameters.BlockSize) 
            {
            // указать идентификатор алгоритма
            case 8: algID = API.CKM_DES_CFB64; break;
            case 1: algID = API.CKM_DES_CFB8;  break;
            
            // при ошибке выбросить исключение
            default: throw new NotSupportedException();
            }
        }
		// параметры алгоритма
		public override Mechanism GetParameters(CAPI.PKCS11.Session sesssion)
		{
			// вернуть параметры алгоритма
		    return new Mechanism(algID, parameters.IV); 
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
