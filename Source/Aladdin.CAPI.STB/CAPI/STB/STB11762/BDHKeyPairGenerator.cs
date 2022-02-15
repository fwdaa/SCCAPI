using System;

///////////////////////////////////////////////////////////////////////////
// Алгоритм генерации ключей обмена СТБ 1176.2
///////////////////////////////////////////////////////////////////////////
namespace Aladdin.CAPI.STB.STB11762
{
    public class BDHKeyPairGenerator : Software.KeyPairGenerator
    {
        // параметры ключей
		private IBDHParameters parameters;

		// конструктор
		public BDHKeyPairGenerator(CAPI.Factory factory, 
            SecurityObject scope, IRand rand, IBDHParameters parameters) 
            
            // сохранить переданные параметры
            : base(factory, scope, rand) { this.parameters = parameters; }

	    public override KeyPair Generate(string keyOID) 
	    {
            // получить фабрику кодирования
            CAPI.KeyFactory keyFactory = Factory.GetKeyFactory(keyOID); 

		    // определить параметры алгоритма
		    Math.BigInteger P = parameters.P; Math.BigInteger G = parameters.G;
            Math.BigInteger X = null; 
            
            // указать генератор случайных чисел
            using (Random random = new Random(Rand))
            do {
                // сгенерировать случайное число
                X = new Math.BigInteger(parameters.R, random);
            }
		    // проверить выполнение требуемых условий
		    while (X.Signum == 0 || X.CompareTo(P) >= 0);

		    // возвести параметр G в степень x
		    Math.BigInteger Y = (new Math.Fp.MontGroup(P)).Power(G, X);

		    // создать открытый ключ 
		    IPublicKey publicKey = new BDHPublicKey(keyFactory, parameters, Y);

            // создать личный ключ 
            using (IPrivateKey privateKey = new BDHPrivateKey(
                Factory, Scope, keyOID, parameters, X))
            { 
                // вернуть созданную пару ключей
                return new KeyPair(publicKey, privateKey, null); 
            }
	    }
    }
}
