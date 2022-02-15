using System;
using Aladdin.PKCS11;

namespace Aladdin.CAPI.GOST.PKCS11.Keyx.GOSTR3410
{
	///////////////////////////////////////////////////////////////////////////////
	// Алгоритм наследования ключа RFC 4357 (2001)
	///////////////////////////////////////////////////////////////////////////////
	public class KeyAgreement2001 : CAPI.PKCS11.KeyAgreement
	{
        // указать способ кодирования чисел
        private const Math.Endian Endian = Math.Endian.LittleEndian; 

		// конструктор
		public KeyAgreement2001(CAPI.PKCS11.Applet applet, ulong kdf) : base(applet)
		
			// закодировать параметры ключа
			{ this.kdf = kdf; } private ulong kdf;

        // создать программный алгоритм
        protected override KeyAgreement CreateSoftwareAlgorithm(IParameters parameters)
        {
            // создать программный алгоритм
            if (kdf == API.CKD_NULL) return new GOST.Keyx.GOSTR3410.ECKeyAgreement2001(); 
        
            // при наличии диверсификации ключа
            if (kdf == API.CKD_CPDIVERSIFY_KDF)
            {
                // преобразовать тип параметров
                GOST.GOSTR3410.INamedParameters gostParameters = 
                    (GOST.GOSTR3410.INamedParameters)parameters; 
            
                // определить идентификатор таблицы подстановок
                string sboxOID = gostParameters.SBoxOID; 
            
                // создать алгоритм диверсификации
                using (KeyDerive keyDerive = Creator.CreateDeriveRFC4357(
                    Applet.Provider, Applet, sboxOID))
                {
                    // проверить поддержку алгоритма
                    if (keyDerive == null) throw new NotSupportedException(); 
                
                    // создать программный алгоритм наследования ключа
                    return new GOST.Keyx.GOSTR3410.ECKeyAgreement2001(keyDerive); 
                }
            }
            // при ошибке выбросить исключение
            throw new NotSupportedException(); 
        }
		// получить параметры
		protected override Mechanism GetParameters(CAPI.PKCS11.Session session, 
			IPublicKey publicKey, byte[] random, int keySize)
        {
	        // преобразовать тип параметров
	        GOST.GOSTR3410.IECParameters gostParameters = 
                (GOST.GOSTR3410.IECParameters)publicKey.Parameters; 

            // определить размер открытого ключа в байтах
            int cbPublicKey = (gostParameters.Order.BitLength + 7) / 8 * 2; 

	        // преобразовать тип ключа
	        GOST.GOSTR3410.IECPublicKey gostPublicKey = (GOST.GOSTR3410.IECPublicKey)publicKey;

	        // получить координаты точки
	        byte[] qx = Math.Convert.FromBigInteger(gostPublicKey.Q.X, Endian, cbPublicKey / 2);
	        byte[] qy = Math.Convert.FromBigInteger(gostPublicKey.Q.Y, Endian, cbPublicKey / 2);

            // объединить координаты точки
            byte[] publicData = Arrays.Concat(qx, qy); 

            // указать параметры алгоритма
            Parameters.CK_GOSTR3410_DERIVE_PARAMS parameters = 
                new Parameters.CK_GOSTR3410_DERIVE_PARAMS(kdf, publicData, random);

            // вернуть параметры алгоритма
            return new Mechanism(API.CKM_GOSTR3410_DERIVE, parameters); 
        }
		// сгенерировать случайные данные
		public override byte[] Generate(IParameters parameters, IRand rand)
		{
			// сгенерировать случайные данные
			byte[] random = new byte[8]; rand.Generate(random, 0, random.Length); return random; 
		}
		// согласовать общий ключ
		public override ISecretKey DeriveKey(IPrivateKey privateKey, 
			IPublicKey publicKey, byte[] random, SecretKeyFactory keyFactory, int keySize)
        {
	        // при использовании эфемерного ключа
	        if (privateKey.Scope == null)
	        {
		        // указать программный алгоритм
		        using (CAPI.KeyAgreement agreement = new GOST.Keyx.GOSTR3410.ECKeyAgreement2001())
                {
		            // выполнить согласование ключа
		            return agreement.DeriveKey(privateKey, publicKey, random, keyFactory, keySize); 
                }
	        }
	        // вызвать базовую функцию
	        return base.DeriveKey(privateKey, publicKey, random, keyFactory, keySize); 
        }
	} 
}
