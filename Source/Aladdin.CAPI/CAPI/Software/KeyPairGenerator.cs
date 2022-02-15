using System; 

namespace Aladdin.CAPI.Software
{
	///////////////////////////////////////////////////////////////////////////
	// Алгоритм генерации программных ключей
	///////////////////////////////////////////////////////////////////////////
	public abstract class KeyPairGenerator : CAPI.KeyPairGenerator
	{
        // конструктор
        public KeyPairGenerator(Factory factory, SecurityObject scope, IRand rand) 
         
            // сохранить переданные параметры
            : base(factory, scope, rand) {} 

        // сгенерировать ключи
		public override KeyPair Generate(
            byte[] keyID, string keyOID, KeyUsage keyUsage, KeyFlags keyFlags)
		{
			// сгенерировать ключи
			using (KeyPair keyPair = Generate(keyOID)) 
            {
                // проверить указание контейнера
                if (!(Scope is Container)) return RefObject.AddRef(keyPair);

		        // записать ключи в контейнер
                return new KeyPair(Scope, Rand, keyPair.PublicKey, 
                    keyPair.PrivateKey, keyPair.KeyID, keyUsage, keyFlags
                ); 
            }
		}
		// сгенерировать ключи
		public abstract KeyPair Generate(string keyOID);
	}
}
