using System;

///////////////////////////////////////////////////////////////////////////
// Алгоритм генерации ключей подписи СТБ 1176.2
///////////////////////////////////////////////////////////////////////////
namespace Aladdin.CAPI.STB.STB11762
{
    public class BDSKeyPairGenerator : Software.KeyPairGenerator
    {
        // параметры ключей
		private IBDSParameters parameters;

		// конструктор
		public BDSKeyPairGenerator(CAPI.Factory factory, 
            SecurityObject scope, IRand rand, IBDSParameters parameters) 
            
            // сохранить переданные параметры
            : base(factory, scope, rand) { this.parameters = parameters; }

	    public override KeyPair Generate(string keyOID) 
	    {
            // получить фабрику кодирования
            CAPI.KeyFactory keyFactory = Factory.GetKeyFactory(keyOID); 

		    // определить параметры алгоритма
		    Math.BigInteger P = parameters.P; Math.BigInteger Q = parameters.Q;
            Math.BigInteger A = parameters.G; Math.BigInteger X = null;

            // указать генератор случайных чисел
            using (Random random = new Random(Rand))
            do {
                // сгенерировать случайное число
                X = new Math.BigInteger(parameters.R, random);
            }
		    // проверить выполнение требуемых условий
		    while (X.Signum == 0 || X.CompareTo(Q) >= 0);

		    // вычислить открытый ключ
		    Math.BigInteger Y = (new Math.Fp.MontGroup(P)).Power(A, X);

		    // создать открытый ключ 
		    IPublicKey publicKey = new BDSPublicKey(keyFactory, parameters, Y);

            // создать личный ключ 
            using (IPrivateKey privateKey = new BDSPrivateKey(
                Factory, Scope, keyOID, parameters, X))
            { 
                // вернуть созданную пару ключей
                return new KeyPair(publicKey, privateKey, null); 
            }
	    }
    }
}
