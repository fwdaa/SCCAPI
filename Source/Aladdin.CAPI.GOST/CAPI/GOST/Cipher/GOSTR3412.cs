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
        public static IBlockCipher Create(
            CAPI.Factory factory, SecurityStore scope, int blockSize)
        {
            // указать идентификатор алгоритма
            string oid = (blockSize == 8) ? ASN1.GOST.OID.gostR3412_64 : ASN1.GOST.OID.gostR3412_128; 
        
            // получить алгоритм шифрования блока
            using (CAPI.Cipher cipher = factory.CreateAlgorithm<CAPI.Cipher>(
                scope, oid, ASN1.Null.Instance))
            {
                // вернуть алгоритм шифрования
                return (cipher != null) ? new GOSTR3412(cipher) : null; 
            }
        }
        // создать блочный алгоритм шифрования со сменой ключа ACPKM
        public static IBlockCipher CreateACPKM(
            CAPI.Factory factory, SecurityStore scope, int blockSize)
        {
            // указать идентификатор алгоритма
            string oid = (blockSize == 8) ? ASN1.GOST.OID.gostR3412_64 : ASN1.GOST.OID.gostR3412_128; 
        
            // указать размер смены ключа
            int N = (blockSize == 8) ? (8 * 1024) : (256 * 1024); 
        
            // получить алгоритм шифрования блока
            using (CAPI.Cipher cipher = factory.CreateAlgorithm<CAPI.Cipher>(
                scope, oid, ASN1.Null.Instance))
            {
                // проверить наличие алгоритма шифрования блока
                if (cipher == null) return null; 
            
                // создать алгоритм смены ключа ACPKM
                using (KeyDerive keyMeshing = new Derive.ACPKM(cipher))
                {
                    // вернуть алгоритм шифрования
                    return new GOSTR3412(cipher, keyMeshing, N); 
                }
            }
        }
        // создать режим шифрования CTR
        public static CAPI.Cipher CreateCTR(CAPI.Factory factory, 
            SecurityStore scope, int blockSize, byte[] iv)
        {
            // указать имя алгоритма
            string name = (blockSize == 8) ? "GOST3412_2015_M" : "GOST3412_2015_K"; 
        
            // создать блочный алгоритм шифрования 
            using (IBlockCipher blockCipher = 
                factory.CreateBlockCipher(scope, name, ASN1.Null.Instance))
            {
                // проверить наличие алгоритма
                if (blockCipher == null) return null; 
            
                // создать режим CTR
                return blockCipher.CreateBlockMode(new CipherMode.CTR(iv, blockSize)); 
            }
        }
        // создать режим шифрования CTR со сменой ключа ACPKM
        public static CAPI.Cipher CreateCTR_ACPKM(CAPI.Factory factory, 
            SecurityStore scope, int blockSize, byte[] iv) 
        {
            // создать блочный алгоритм шифрования 
            using (IBlockCipher blockCipher = CreateACPKM(factory, scope, blockSize))
            {
                // проверить наличие алгоритма
                if (blockCipher == null) return null; 
            
                // создать режим CTR
                return blockCipher.CreateBlockMode(new CipherMode.CTR(iv, blockSize)); 
            }
        }
        // создать алгоритм вычисления имитовставки
        public static Mac CreateOMAC(CAPI.Factory factory, SecurityStore scope, int blockSize)
        {
            // указать имя алгоритма
            String name = (blockSize == 8) ? "GOST3412_2015_M" : "GOST3412_2015_K"; 
        
            // создать блочный алгоритм шифрования
            using (IBlockCipher blockCipher = factory.CreateBlockCipher(scope, name, ASN1.Null.Instance))
            {
                // проверить наличие алгоритма
                if (blockCipher == null) return null; byte[] start = new byte[blockSize]; 
            
                // создать алгоритм выработки имитовставки
                return CAPI.MAC.OMAC1.Create(blockCipher, start); 
            }
        }
        // конструктор
	    public GOSTR3412(CAPI.Cipher gostr3412, KeyDerive keyMeshing, int N) : base(gostr3412) 
        {
            // проверить корректность параметров
            if ((N % gostr3412.BlockSize) != 0) throw new ArgumentException(); 

            // указать способ смены ключа
            this.keyMeshing = RefObject.AddRef(keyMeshing); this.N = N; 
        } 
        // конструктор
	    public GOSTR3412(CAPI.Cipher gostr3412)  

		    // сохранить переданные параметры
		    : base(gostr3412) { this.keyMeshing = null; N = 0; }

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
                return new Mode.GOSTR3412.ECB(Engine, keyMeshing, N, PaddingMode.Any);  
            }
            if (mode is CipherMode.CBC) 
            {
                // вернуть режим шифрования CBC
                return new Mode.GOSTR3412.CBC(Engine, (CipherMode.CBC)mode, keyMeshing, N, PaddingMode.Any);  
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
