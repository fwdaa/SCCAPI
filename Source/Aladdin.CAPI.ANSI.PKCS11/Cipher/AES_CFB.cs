using System;
using Aladdin.PKCS11; 

namespace Aladdin.CAPI.ANSI.PKCS11.Cipher
{
	///////////////////////////////////////////////////////////////////////////////
	// Алгоритм шифрования AES в режиме CFB
	///////////////////////////////////////////////////////////////////////////////
	public class AES_CFB : CAPI.PKCS11.BlockMode
	{
        // идентификатор алгоритма, размеры ключей и параметры алгоритма
        private ulong algID; private int[] keySizes; private CipherMode.CFB parameters;

		// конструктор
		public AES_CFB(CAPI.PKCS11.Applet applet, int[] keySizes, CipherMode.CFB parameters)

			// сохранить переданные параметры
			: base(applet, PaddingMode.None) 
		{
            // в зависимости от размера блока
            this.parameters = parameters; switch (parameters.BlockSize) 
            {
            // указать идентификатор алгоритма
            case 16: algID = API.CKM_AES_CFB128; break;
            case  8: algID = API.CKM_AES_CFB64 ; break;
            case  1: algID = API.CKM_AES_CFB8  ; break;
            
            // при ошибке выбросить исключение
            default: throw new NotSupportedException();
            }
            // указать допустимые размеры ключей
            if (keySizes != null) this.keySizes = keySizes; 
            else {
                // получить информацию алгоритма
                MechanismInfo info = applet.GetAlgorithmInfo(algID); 
            
                // указать допустимые размеры ключей
                this.keySizes = CAPI.KeySizes.Range(info.MinKeySize, info.MaxKeySize, 8); 
            }
		} 
		// параметры алгоритма
		public override Mechanism GetParameters(CAPI.PKCS11.Session sesssion)
		{
			// вернуть параметры алгоритма
		    return new Mechanism(algID, parameters.IV); 
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
