///////////////////////////////////////////////////////////////////////////
// Алгоритм генерации двойных ключей СТБ 1176.2
///////////////////////////////////////////////////////////////////////////
namespace Aladdin.CAPI.STB.STB11762
{
    public class BDSBDHKeyPairGenerator : Software.KeyPairGenerator
    {
        // параметры ключей
		private IBDSBDHParameters parameters;

		// конструктор
		public BDSBDHKeyPairGenerator(CAPI.Factory factory, 
            SecurityObject scope, IRand rand, IBDSBDHParameters parameters) 
            
            // сохранить переданные параметры
            : base(factory, scope, rand) { this.parameters = parameters; }

	    public override KeyPair Generate(string keyOID) 
	    {
            // получить фабрику кодирования
            CAPI.KeyFactory keyFactory = Factory.GetKeyFactory(keyOID); 

		    // создать алгоритм генерации ключей
		    using (Software.KeyPairGenerator bdsGenerator = 
			    new BDSKeyPairGenerator(Factory, Scope, Rand, parameters))
            {
                // сгенерировать пару ключей
                using (KeyPair bdsKeyPair = bdsGenerator.Generate(keyOID))
                { 
                    // создать алгоритм генерации ключей
                    using (Software.KeyPairGenerator bdhGenerator =
                        new BDHKeyPairGenerator(Factory, Scope, Rand, parameters))
                    {
                        // сгенерировать пару ключей
                        using (KeyPair bdhKeyPair = bdhGenerator.Generate(keyOID))
                        {
                            // создать открытый ключ подписи/обмена
                            IBDSBDHPublicKey publicKey = new BDSBDHPublicKey(
                                keyFactory, parameters,
                                ((IBDSPublicKey)bdsKeyPair.PublicKey).Y,
                                ((IBDHPublicKey)bdhKeyPair.PublicKey).Y
                            );
                            // создать личный ключ подписи/обмена
                            using (IBDSBDHPrivateKey privateKey = new BDSBDHPrivateKey(
                                Factory, Scope, keyOID, parameters,
                                ((IBDSPrivateKey)bdsKeyPair.PrivateKey).X,
                                ((IBDHPrivateKey)bdhKeyPair.PrivateKey).X))
                            { 
                                // вернуть созданную пару ключей
                                return new KeyPair(publicKey, privateKey, null);
                            }
                        }
                    }
                }
            } 
	    }
    }
}
