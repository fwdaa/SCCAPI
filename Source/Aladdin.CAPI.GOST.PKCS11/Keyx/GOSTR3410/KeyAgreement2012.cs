using System;
using Aladdin.PKCS11;

namespace Aladdin.CAPI.GOST.PKCS11.Keyx.GOSTR3410
{
	///////////////////////////////////////////////////////////////////////////////
	// Алгоритм наследования ключа RFC 4357 (2012)
	///////////////////////////////////////////////////////////////////////////////
	public class KeyAgreement2012 : CAPI.PKCS11.KeyAgreement
	{
        // указать способ кодирования чисел
        private const Math.Endian Endian = Math.Endian.LittleEndian; 

        // тип диверсификации
		private ulong kdf;

		// конструктор
		public KeyAgreement2012(CAPI.PKCS11.Applet applet, ulong kdf)
			
			// сохранить переданные параметры
			: base(applet) { this.kdf = kdf; }

        // создать программный алгоритм
        protected override KeyAgreement CreateSoftwareAlgorithm(IParameters parameters)
        {
            // создать программный алгоритм
            if (kdf == API.CKD_NULL) return new GOST.Keyx.GOSTR3410.ECKeyAgreement2012(); 
        
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
                    return new GOST.Keyx.GOSTR3410.ECKeyAgreement2012(keyDerive); 
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

	        // преобразовать тип ключа
	        GOST.GOSTR3410.IECPublicKey gostPublicKey = (GOST.GOSTR3410.IECPublicKey)publicKey;

            // определить размер открытого ключа в байтах
            int cbPublicKey = (gostParameters.Order.BitLength + 7) / 8 * 2; int offset = 0; 

	        // получить координаты точки
	        byte[] qx = Math.Convert.FromBigInteger(gostPublicKey.Q.X, Endian, cbPublicKey / 2);
	        byte[] qy = Math.Convert.FromBigInteger(gostPublicKey.Q.Y, Endian, cbPublicKey / 2);

            // выделить буфер требуемого размера
            byte[] buffer = new byte[4 + 4 + cbPublicKey + 4 + random.Length]; 
        
            // закодировать тип диверсификации
            Math.Convert.FromUInt32((uint)kdf, Endian, buffer, offset); offset += 4; 

            // закодировать размер ключа
            Math.Convert.FromInt32(cbPublicKey, Endian, buffer, offset); offset += 4;

            // скопировать координаты точки
            Array.Copy(qx, 0, buffer, offset, cbPublicKey / 2); offset += cbPublicKey / 2; 
            Array.Copy(qy, 0, buffer, offset, cbPublicKey / 2); offset += cbPublicKey / 2; 

            // закодировать размер случайных данных
            Math.Convert.FromInt32(random.Length, Endian, buffer, offset); offset += 4; 

            // скопировать случайные данные
            Array.Copy(random, 0, buffer, offset, random.Length); offset += random.Length; 

            // вернуть параметры алгоритма
            return new Mechanism(API.CKM_GOSTR3410_2012_DERIVE, buffer); 
        }
        // размер случайных данных
        protected virtual int RandomSize { get { return 8; }}

		// сгенерировать случайные данные
		public override byte[] Generate(IParameters parameters, IRand rand)
		{
			// сгенерировать случайные данные
			byte[] random = new byte[RandomSize];             

			// сгенерировать случайные данные
            rand.Generate(random, 0, random.Length); return random; 
		}
	} 
}
