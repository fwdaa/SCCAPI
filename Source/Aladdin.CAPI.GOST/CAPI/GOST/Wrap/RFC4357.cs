using System; 
using System.IO; 

///////////////////////////////////////////////////////////////////////////
// Алгоритм шифрования ключа ГОСТ 28147-89
///////////////////////////////////////////////////////////////////////////
namespace Aladdin.CAPI.GOST.Wrap
{
    public class RFC4357 : CAPI.KeyWrap
    {
        // флаги алгоритмов шифрования ключа
        public const int NoneSBoxA = 0x0001; public const int CProSBoxA = 0x0010;
        public const int NoneSBoxB = 0x0002; public const int CProSBoxB = 0x0020; 
        public const int NoneSBoxC = 0x0004; public const int CProSBoxC = 0x0040; 
        public const int NoneSBoxD = 0x0008; public const int CProSBoxD = 0x0080; 
        public const int NoneSBoxZ = 0x0100; public const int CProSBoxZ = 0x0200; 
    
        // алгоритмы шифрования и выработки имитовставки
        private CAPI.Cipher cipher; private Mac macAlgorithm;
        // алгоритм диверсификации и случайные данные
        private KeyDerive keyDerive; private byte[] ukm;

        // конструктор
	    public RFC4357(CAPI.Cipher cipher, Mac macAlgorithm, byte[] ukm)
        {
            // сохранить переданные параметры
		    this.cipher       = RefObject.AddRef(cipher      ); 
		    this.macAlgorithm = RefObject.AddRef(macAlgorithm); 
        
            // сохранить переданные параметры
            this.keyDerive = new CAPI.Derive.NOKDF(Engine.GOST28147.Endian); this.ukm = ukm;
        }
        // конструктор
	    public RFC4357(CAPI.Cipher cipher, Mac macAlgorithm, KeyDerive keyDerive, byte[] ukm)
        {
            // сохранить переданные параметры
		    this.cipher       = RefObject.AddRef(cipher      ); 
		    this.macAlgorithm = RefObject.AddRef(macAlgorithm); 
        
            // сохранить переданные параметры
            this.keyDerive = RefObject.AddRef(keyDerive); this.ukm = ukm;
        }
        // освободить ресурсы
        protected override void OnDispose()
        { 
            // освободить ресурсы
            RefObject.Release(keyDerive); RefObject.Release(macAlgorithm);
        
            // освободить ресурсы
            RefObject.Release(cipher); base.OnDispose();
        }
        // тип ключа
        public override SecretKeyFactory KeyFactory { get { return cipher.KeyFactory; }}
	    // размер ключей
	    public override int[] KeySizes { get { return cipher.KeySizes; }}

        // зашифровать ключ
	    public override byte[] Wrap(IRand rand, ISecretKey key, ISecretKey wrappedKey) 
	    {
		    // проверить тип ключа
		    byte[] CEK = wrappedKey.Value; if (CEK == null) throw new InvalidKeyException();
			
            // диверсифицировать ключ
            using (ISecretKey newKey = keyDerive.DeriveKey(key, ukm, cipher.KeyFactory, 32))
            { 
                // зашифровать ключ
                byte[] encrypted = cipher.Encrypt(newKey, PaddingMode.None, CEK, 0, CEK.Length);

                // вычислить имитовставку
                byte[] imito = macAlgorithm.MacData(newKey, CEK, 0, CEK.Length); 

                // вернуть зашифрованный ключ и имитовставку
                return Arrays.Concat(encrypted, imito);
            }
 	    }
        // расшифровать ключ
	    public override ISecretKey Unwrap(ISecretKey key, byte[] wrappedCEK, SecretKeyFactory keyFactory)
	    {
		    // определить размер зашифрованных данных
            int sizeCEK = wrappedCEK.Length - 4;

		    // проверить размер зашифрованного ключа
		    if (sizeCEK != 32 && sizeCEK != 64) throw new InvalidDataException();
 
            // диверсифицировать ключ
            using (ISecretKey newKey = keyDerive.DeriveKey(key, ukm, cipher.KeyFactory, 32))
            { 
                // расшифровать ключ
                byte[] CEK = cipher.Decrypt(newKey, PaddingMode.None, wrappedCEK, 0, sizeCEK); 

                // вычислить имитовставку
                byte[] imito = macAlgorithm.MacData(newKey, CEK, 0, CEK.Length);

                // проверить совпадение имитовставки
                if (!Arrays.Equals(imito, 0, wrappedCEK, sizeCEK, 4)) throw new InvalidDataException();

                // вернуть расшифрованный ключ
                return keyFactory.Create(CEK);
            }
	    }
    }
}
