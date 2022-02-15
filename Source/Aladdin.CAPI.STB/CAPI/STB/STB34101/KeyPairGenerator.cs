using System;

///////////////////////////////////////////////////////////////////////////
// Алгоритм генерации двойных ключей СТБ 34.101
///////////////////////////////////////////////////////////////////////////
namespace Aladdin.CAPI.STB.STB34101
{
    public class KeyPairGenerator : Software.KeyPairGenerator
    {
        // параметры ключей
		private IParameters parameters;	

		// конструктор
		public KeyPairGenerator(CAPI.Factory factory, 
            SecurityObject scope, IRand rand, IParameters parameters) 
            
            // сохранить переданные параметры
            : base(factory, scope, rand) { this.parameters = parameters; }

        public override KeyPair Generate(string keyOID) 
	    {
            // получить фабрику кодирования
            CAPI.KeyFactory keyFactory = Factory.GetKeyFactory(keyOID); 

		    // получить параметры алгоритма
		    EC.Curve ec = parameters.Curve; Math.BigInteger d = null;
            
		    // создать базовую точку эллиптической кривой
		    EC.Point G = parameters.Generator; 
			
		    // получить параметры алгоритма
            Math.BigInteger q = parameters.Order; int bitsQ = q.BitLength;

            // указать генератор случайных чисел
            using (Random random = new Random(Rand))
            do { 
		        // сгенерировать случайное число
                d = new Math.BigInteger(bitsQ, random);
            }
		    // проверить выполнение требуемых условий
            while (d.Signum == 0 || d.CompareTo(q) >= 0); 

		    // умножить базовую точку на число
		    EC.Point Q = ec.Multiply(G, d); 

		    // создать открытый ключ 
		    IPublicKey publicKey = new PublicKey(keyFactory, parameters, Q);

            // создать личный ключ 
            using (IPrivateKey privateKey = new PrivateKey(
                Factory, Scope, keyOID, parameters, d))
            { 
                // вернуть созданную пару ключей
                return new KeyPair(publicKey, privateKey, null); 
            }
	    }
    }
}
