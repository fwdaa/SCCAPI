using System;
using Aladdin.PKCS11; 

namespace Aladdin.CAPI.ANSI.PKCS11.Cipher
{
	///////////////////////////////////////////////////////////////////////////////
	// Алгоритм шифрования RC2 в режиме CBC
	///////////////////////////////////////////////////////////////////////////////
	public class RC2_CBC : CAPI.PKCS11.BlockMode
	{
		// эффективное число битов ключа и параметры режима
		private int effectiveKeyBits; private int[] keySizes; private CipherMode.CBC parameters;  

		// конструктор
		public RC2_CBC(CAPI.PKCS11.Applet applet, int effectiveKeyBits, 

			// сохранить переданные параметры
			int[] keySizes, CipherMode.CBC parameters) : base(applet, PaddingMode.None) 
		{ 
            // проверить размер блока
            if (parameters.BlockSize != 8) throw new NotSupportedException(); 

			// сохранить переданные параметры
			this.effectiveKeyBits = effectiveKeyBits; this.parameters = parameters;

            // указать допустимые размеры ключей
            if (keySizes != null) this.keySizes = keySizes; 
            else {
                // получить информацию алгоритма
                MechanismInfo info = applet.GetAlgorithmInfo(API.CKM_RC2_CBC); 
            
                // указать допустимые размеры ключей
                this.keySizes = CAPI.KeySizes.Range((info.MinKeySize + 7) / 8, info.MaxKeySize / 8); 
            }
        } 
		// параметры алгоритма
		public override Mechanism GetParameters(CAPI.PKCS11.Session sesssion)
		{
            // указать параметры алгоритма
            Parameters.CK_RC2_CBC_PARAMS rc2Parameters = 
                new Parameters.CK_RC2_CBC_PARAMS(effectiveKeyBits, parameters.IV); 

	        // вернуть параметры алгоритма
	        return new Mechanism(API.CKM_RC2_CBC, rc2Parameters); 
		}
        // тип ключей
        public override SecretKeyFactory KeyFactory { get { return Keys.RC2.Instance; }}
		// размер ключа в байтах
		public override int[] KeySizes { get { return keySizes; }}
		// размер блока
		public override int BlockSize { get { return 8; }} 

		// режим алгоритма
		public override CipherMode Mode { get { return parameters; }}
	} 
}
