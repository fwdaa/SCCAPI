using System;

namespace Aladdin.CAPI.PKCS11.Athena.X962
{
    ///////////////////////////////////////////////////////////////////////////
    // Алгоритм генерации ключей EC/ECDSA
    ///////////////////////////////////////////////////////////////////////////
    public class KeyPairGenerator : ANSI.PKCS11.X962.KeyPairGenerator
    {
	    // конструктор
	    public KeyPairGenerator(CAPI.PKCS11.Applet applet, SecurityObject scope, 

            // сохранить переданные параметры
            IRand rand, ANSI.X962.IParameters parameters) : base(applet, scope, rand, parameters) {}

		// сгенерировать пару ключей
		public override KeyPair Generate(byte[] keyID, string keyOID, KeyUsage keyUsage, KeyFlags keyFlags)
        {
            // сгенерировать пару ключей
            using (KeyPair keyPair = Generate(keyOID, keyUsage))
            {
                // проверить необходимость записи
                if (!(Scope is Container)) return RefObject.AddRef(keyPair); 

                // записать пару ключей на смарт-карту
                return ((Container)Scope).ImportKeyPair(
                    Rand, keyPair.PublicKey, keyPair.PrivateKey, keyUsage, keyFlags
                ); 
            }
        }
    }
}
