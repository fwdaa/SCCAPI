using System;
using Aladdin.PKCS11;

namespace Aladdin.CAPI.GOST.PKCS11.Wrap
{
	///////////////////////////////////////////////////////////////////////////////
	// Алгоритм шифрования ключа с выработкой имитовставки
	///////////////////////////////////////////////////////////////////////////////
	public class RFC4357 : CAPI.PKCS11.KeyWrap
	{
        // указать способ кодирования чисел
        private const Math.Endian Endian = Math.Endian.LittleEndian; 

        // алгоритм диверсификации ключа, параметры ключа и случайные данные
        private CAPI.KeyDerive keyDerive; private byte[] encodedOID; private byte[] ukm;

		// конструктор
		public RFC4357(CAPI.PKCS11.Applet applet, ulong kdf, 
            string sboxOID, byte[] ukm) : base(applet) 
		{
            if (kdf == API.CKD_NULL)
            {
                // указать алгоритм наследования ключа
                keyDerive = new CAPI.Derive.NOKDF(Endian);
            }
            else if (kdf == API.CKD_CPDIVERSIFY_KDF)
            {
                // указать алгоритм наследования ключа
                keyDerive = Creator.CreateDeriveRFC4357(applet.Provider, applet, sboxOID); 

                // при ошибке выбросить исключение
                if (keyDerive == null) throw new NotSupportedException(); 
            }
            // при ошибке выбросить исключение
            else throw new NotSupportedException(); 			
            
            // закодировать параметры алгоритма
			encodedOID = new ASN1.ObjectIdentifier(sboxOID).Encoded; this.ukm = ukm; 
		}
		// конструктор
		public RFC4357(CAPI.PKCS11.Applet applet, string sboxOID, byte[] ukm) 
            
            // сохранить переданные параметры
            : this(applet, API.CKD_NULL, sboxOID, ukm) {}

        // деструктор
        protected override void OnDispose()
        {
            // освободить выделенные ресурсы
            RefObject.Release(keyDerive); base.OnDispose();
        }
		// параметры алгоритма
		protected override Mechanism GetParameters(CAPI.PKCS11.Session session, IRand rand)
		{ 
			// вернуть параметры алгоритма
			return new Mechanism(API.CKM_GOST28147_KEY_WRAP, ukm); 
		}
		// атрибуты ключа
		protected override CAPI.PKCS11.Attribute[] GetKeyAttributes(int keySize)
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
        public override SecretKeyFactory KeyFactory { get { return Keys.GOST.Instance; }}

	    public override byte[] Wrap(IRand rand, ISecretKey KEK, ISecretKey CEK) 
        {
            // выполнить диверсификацию ключа
            using (ISecretKey key = keyDerive.DeriveKey(KEK, ukm, KeyFactory, 32))
            {
                // вызвать базовую функцию
                return base.Wrap(rand, key, CEK); 
            }
        }
	    public override ISecretKey Unwrap(ISecretKey KEK, byte[] wrappedCEK, SecretKeyFactory keyFactory) 
        {
            // выполнить диверсификацию ключа
            using (ISecretKey key = keyDerive.DeriveKey(KEK, ukm, KeyFactory, 32))
            {
                // вызвать базовую функцию
                return base.Unwrap(key, wrappedCEK, keyFactory); 
            }
        }
	}
}
