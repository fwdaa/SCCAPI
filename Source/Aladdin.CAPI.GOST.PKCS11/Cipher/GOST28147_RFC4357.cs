using System;
using Aladdin.PKCS11;

namespace Aladdin.CAPI.GOST.PKCS11.Cipher
{
	///////////////////////////////////////////////////////////////////////////////
	// Алгоритм шифрования ГОСТ 28147-89 с указанием набора параметров
	///////////////////////////////////////////////////////////////////////////////
	public class GOST28147_RFC4357 : CAPI.PKCS11.BlockMode
	{
		// параметры ключа и синхропосылка
		private byte[] encodedOID; private byte[] iv; 

        // конструктор
		public GOST28147_RFC4357(CAPI.PKCS11.Applet applet, string paramsOID, byte[] iv) : 

			// сохранить переданные параметры
			base(applet, PaddingMode.None) 
		{
			// закодировать параметры алгоритма
			encodedOID = new ASN1.ObjectIdentifier(paramsOID).Encoded; this.iv = iv; 
		}
		// параметры алгоритма
		public override Mechanism GetParameters(CAPI.PKCS11.Session session)
		{ 
			// вернуть параметры алгоритма
			return new Mechanism(API.CKM_GOST28147, iv); 
		}
		// атрибуты ключа
		public override CAPI.PKCS11.Attribute[] GetKeyAttributes(int keySize)
		{ 
			// атрибуты ключа
			return new CAPI.PKCS11.Attribute[] { 

				// указать требуемые атрибуты
				Applet.Provider.CreateAttribute(API.CKA_KEY_TYPE, API.CKK_GOST28147),  

				// указать требуемые атрибуты
				Applet.Provider.CreateAttribute(API.CKA_GOST28147_PARAMS, encodedOID)
			}; 
		}
        // тип ключей
        public override SecretKeyFactory KeyFactory { get { return Keys.GOST28147.Instance; }}
		// размер ключа в байтах
		public override int[] KeySizes { get { return new int[] {32}; }}
		// размер блока
		public override int BlockSize { get { return 8; }} 

		// режим алгоритма
		public override CipherMode Mode { get { return new CipherMode.CFB(iv, 8); }}
	} 
}
