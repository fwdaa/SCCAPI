using System;

namespace Aladdin.CAPI.GOST.Cipher
{
    ///////////////////////////////////////////////////////////////////////////
    // Алгоритм шифрования ГОСТ P34.12-2015
    ///////////////////////////////////////////////////////////////////////////
    public class GOSTR3412 : BlockCipher
    {
         // режим смены ключа и размер смены ключа
        private KeyDerive keyMeshing; private int N; 

        // создать алгоритм из фаборики
        public static IBlockCipher Create(CAPI.Factory factory, SecurityStore scope, int blockSize)
        {
            // указать идентификатор алгоритма
            string oid = (blockSize == 8) ? ASN1.GOST.OID.gostR3412_64 : ASN1.GOST.OID.gostR3412_128; 
        
            // закодировать параметры алгоритма
            ASN1.ISO.AlgorithmIdentifier cipherParameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(oid), ASN1.Null.Instance
            );
            // получить алгоритм шифрования блока
            using (CAPI.Cipher cipher = factory.CreateAlgorithm<CAPI.Cipher>(scope, cipherParameters))
            {
                // вернуть алгоритм шифрования
                return new GOSTR3412(cipher, PaddingMode.Any); 
            }
        }
        public static CAPI.Cipher CreateCTR_ACPKM(CAPI.Factory factory, SecurityStore scope, int blockSize, byte[] iv)
        {
            // указать идентификатор алгоритма
            string oid = (blockSize == 8) ? ASN1.GOST.OID.gostR3412_64 : ASN1.GOST.OID.gostR3412_128; 

            // указать размер смены ключа
            int N = (blockSize == 8) ? (8 * 1024) : (256 * 1024); 
        
            // закодировать параметры алгоритма
            ASN1.ISO.AlgorithmIdentifier cipherParameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(oid), ASN1.Null.Instance
            );
            // получить алгоритм шифрования блока
            using (CAPI.Cipher cipher = factory.CreateAlgorithm<CAPI.Cipher>(scope, cipherParameters))
            {
                // проверить наличие алгоритма шифрования блока
                if (cipher == null) return null; 
            
                // создать алгоритм смены ключа для OMAC-ACPKM
                using (KeyDerive keyMeshing = new Derive.ACPKM(cipher))
                {
                    // указать синхропосылку для шифрования
                    byte[] ivCTR = new byte[iv.Length - 8]; Array.Copy(iv, 0, ivCTR, 0, ivCTR.Length); 
                        
                    // указать параметры режима
                    CipherMode.CTR ctrParameters = new CipherMode.CTR(ivCTR, cipher.BlockSize); 
                            
                    // создать режим CTR со специальной сменой ключа
                    return new Mode.GOSTR3412.CTR(cipher, ctrParameters, keyMeshing, N); 
                }
            }
        }
        public static CAPI.Cipher CreateCTR_ACPKM_OMAC(CAPI.Factory factory, SecurityStore scope, int blockSize, byte[] iv)
        {
            // создать блочный алгоритм шифрования
            using (IBlockCipher blockCipher = Create(factory, scope, blockSize))
            {
                // создать режим CTR со специальной сменой ключа
                using (CAPI.Cipher ctrACPKM = CreateCTR_ACPKM(factory, scope, blockSize, iv))
                {
                    // указать начальную синхропосылку
                    byte[] start = new byte[blockSize]; 

                    // создать алгоритм выработки имитовставки
                    using (Mac omac = CAPI.MAC.OMAC1.Create(blockCipher, start))
                    {
                        // закодировать параметры алгоритма
                        ASN1.ISO.AlgorithmIdentifier hmacParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.GOST.OID.gostR3411_2012_HMAC_256), ASN1.Null.Instance
                        );
                        // создать алгоритм HMAC
                        using (Mac hmac = factory.CreateAlgorithm<Mac>(scope, hmacParameters))
                        {
                            // проверить наличие алгоритма шифрования блока
                            if (hmac == null) return null; byte[] seed = new byte[8];

                            // указать синхропосылку для генерации ключей
                            Array.Copy(iv, iv.Length - 8, seed, 0, seed.Length);
                        
                            // обьединить имитовставку с режимом
                            return new GOSTR3412ACPKM_MAC(ctrACPKM, omac, hmac, seed); 
                        }
                    }
                }
            }
        }
        // конструктор
	    public GOSTR3412(CAPI.Cipher gostr3412, KeyDerive keyMeshing, int N, PaddingMode padding)  

		    // сохранить переданные параметры
		    : base(gostr3412, padding) 
        {
            // проверить корректность параметров
            if ((N % gostr3412.BlockSize) != 0) throw new ArgumentException(); 

            // указать способ смены ключа
            this.keyMeshing = RefObject.AddRef(keyMeshing); this.N = N; 
        } 
        // конструктор
	    public GOSTR3412(CAPI.Cipher gostr3412, PaddingMode padding)  

		    // сохранить переданные параметры
		    : base(gostr3412, padding) { this.keyMeshing = null; N = 0; }

        // освободить ресурсы
        protected override void OnDispose() 
        { 
            // освободить ресурсы
            RefObject.Release(keyMeshing); base.OnDispose();
        }
        // создать режим шифрования
        public override CAPI.Cipher CreateBlockMode(CipherMode mode)  
        {
            if (mode is CipherMode.ECB) 
            {
                // вернуть режим шифрования ECB
                return new Mode.GOSTR3412.ECB(Engine, keyMeshing, N, Padding);  
            }
            if (mode is CipherMode.CBC) 
            {
                // вернуть режим шифрования CBC
                return new Mode.GOSTR3412.CBC(Engine, (CipherMode.CBC)mode, keyMeshing, N, Padding);  
            }
            if (mode is CipherMode.CFB) 
            {
                // вернуть режим шифрования CFB
                return new Mode.GOSTR3412.CFB(Engine, (CipherMode.CFB)mode, keyMeshing, N);  
            }
            if (mode is CipherMode.OFB) 
            {
                // вернуть режим шифрования OFB
                return new Mode.GOSTR3412.OFB(Engine, (CipherMode.OFB)mode, keyMeshing, N);  
            }
            if (mode is CipherMode.CTR) 
            {
                // вернуть режим шифрования CFB
                return new Mode.GOSTR3412.CTR(Engine, (CipherMode.CTR)mode, keyMeshing, N);  
            }
            // при ошибке выбросить исключение
            throw new NotSupportedException(); 
        }
    }
}
