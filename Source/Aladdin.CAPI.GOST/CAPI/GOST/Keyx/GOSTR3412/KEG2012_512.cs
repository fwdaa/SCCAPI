using System;
using System.IO;

namespace Aladdin.CAPI.GOST.Keyx.GOSTR3412
{
    ///////////////////////////////////////////////////////////////////////////
    // Формирование общего ключа KEG (личный ключ 64 байта)
    ///////////////////////////////////////////////////////////////////////////
    public class KEG2012_512 : GOSTR3410.ECKeyAgreement2012 
    {
        // размер случайных данных
        protected override int RandomSize { get { return 32; }}

        // сгенерировать случайные данные
        public override byte[] Generate(IParameters parameters, IRand rand)
        {
            // выделить буфер для случайных данных
            byte[] random = new byte[RandomSize]; 
            
            // сгенерировать случайные данные
            rand.Generate(random, 0, random.Length); return random; 
        }
 	    // согласовать общий ключ на стороне получателя
	    public override ISecretKey DeriveKey(IPrivateKey privateKey, 
            IPublicKey publicKey, byte[] random, SecretKeyFactory keyFactory, int keySize)
        {
            // проверить указание размера
            if (keySize < 0) keySize = 64; if (keySize != 64) throw new InvalidDataException();
        
            // скопировать часть случайных данных
            byte[] r = new byte[16]; Array.Copy(random, 0, r, 0, r.Length);
        
            // для случайных данных
            bool zero = true; for (int i = 0; i < r.Length; i++)
            {
                // проверить отсутствие нулевых данных
                if (random[i] != 0) { zero = false; break; }
            }
            // скорректировать нулевые данные
            Array.Reverse(r); if (zero) r[0] = 0x1; 
        
            // преобразовать тип параметров
            GOST.GOSTR3410.IECParameters parameters = 
                (GOST.GOSTR3410.IECParameters) privateKey.Parameters; 
        
            // определить размер личного ключа
            int privateKeyLength = (parameters.Order.BitLength + 7) / 8; 
        
            // проверить корректность размера
            if (keySize != privateKeyLength) throw new InvalidDataException();
        
            // согласовать общий ключ
            return base.DeriveKey(privateKey, publicKey, r, keyFactory, keySize); 
        }
    }
}
