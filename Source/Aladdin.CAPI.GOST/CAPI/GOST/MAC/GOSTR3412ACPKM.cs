using System;

namespace Aladdin.CAPI.GOST.MAC
{
	///////////////////////////////////////////////////////////////////////////
	// Алгоритм вычисления имитовставки OMAC
	///////////////////////////////////////////////////////////////////////////
    public class GOSTR3412ACPKM : CAPI.MAC.OMAC1
    {
        // алгоритм смены ключей и размер ключа
        private MasterACPKM masterACPKM; private int keySize; 

        // создать алгоритм вычисления имитовставки OMAC
        public static GOSTR3412ACPKM Create(CAPI.Cipher cipher, int N, int T, int macSize)
        {
            // создать алгоритм смены ключа для OMAC-ACPKM
            using (MasterACPKM masterACPKM = new MasterACPKM(cipher, T))
            {
                // указать параметры режима
                CipherMode.CBC parameters = new CipherMode.CBC(
                    new byte[cipher.BlockSize]
                ); 
                // создать режим CBC со специальной сменой ключа
                using (CAPI.Cipher modeCBC = new Mode.GOSTR3412.CBC(
                    cipher, parameters, masterACPKM, N))
                {
                    // создать алгоритм вычисления имитовставки OMAC
                    return new GOSTR3412ACPKM(modeCBC, masterACPKM, macSize); 
                }
            }
        }
        // конструктор
        private GOSTR3412ACPKM(CAPI.Cipher modeCBC, MasterACPKM masterACPKM, int macSize) 
            
            // сохранить переданные параметры
            : base(modeCBC, macSize) { this.masterACPKM = RefObject.AddRef(masterACPKM); }

        // освободить ресурсы
        protected override void OnDispose() 
        { 
            // освободить ресурсы
            RefObject.Release(masterACPKM); base.OnDispose();
        }
	    // инициализировать алгоритм
	    public override void Init(ISecretKey key) 
        {
            // инициализировать алгоритм
            masterACPKM.Init(key); keySize = key.Length; 

            // создать новый ключ
            using (ISecretKey newKey = masterACPKM.DeriveKey(
                null, null, Keys.GOSTR3412.Instance, key.Length))
            {
                // инициализировать алгоритм
                base.Init(newKey);
            }
        }
	    // завершить преобразование
	    protected override void Finish(
            byte[] data, int dataOff, int dataLen, byte[] mac, int macOff)
        {
            // завершить преобразование 
            base.Finish(data, dataOff, dataLen, mac, macOff); 

            // освободить ресурсы
            masterACPKM.Finish(); 
        }
        // получить дополнительный ключ
        protected override byte[] GetXorK1() 
        { 
            // создать дополнительный ключ
            return masterACPKM.GetXorK1(keySize); 
        }
        // создать дополнительный ключ
        protected override byte[] CreateXorK1(ISecretKey key) { return null; }

        ///////////////////////////////////////////////////////////////////////////////
        // Алгоритм смены ключа для OMAC-ACPKM
        ///////////////////////////////////////////////////////////////////////////////
        private class MasterACPKM : KeyDerive
        {
            // режим CTR-ACPKM
            private BlockMode mode; private Transform transform; 
            
            // последние сгенерированные ключи и их размер
            private byte[] encrypted; private int length; private int blockSize; 

            // конструктор
            public MasterACPKM(CAPI.Cipher cipher, int N)
            { 
                // выделить буфер для синхропосылки
                blockSize = cipher.BlockSize; byte[] iv = new byte[blockSize / 2]; 

                // инициализировать синхропосылку
                for (int i = 0; i < iv.Length; i++) iv[i] = 0xFF; 

                // указать параметры алгоритма
                CipherMode.CTR parameters = new CipherMode.CTR(iv, cipher.BlockSize); 

                // создать алгоритм смены ключа
                using (KeyDerive keyMeshing = new Derive.ACPKM(cipher))
                { 
                    // создать режим CTR
                    mode = new Mode.GOSTR3412.CTR(cipher, parameters, keyMeshing, N); 
                }
                // инициализировать переменные
                transform = null; encrypted = new byte[0]; length = 0; 
            }  
            // освободить ресурсы
            protected override void OnDispose() 
            { 
                // обнулить сгенерированные ключи
                for (int i = 0; i < encrypted.Length; i++) encrypted[i] = 0; 

                // освободить ресурсы
                RefObject.Release(transform); RefObject.Release(mode); base.OnDispose();
            }
	        // инициализировать алгоритм
	        public void Init(ISecretKey key) 
            {
                // освободить ресурсы
                RefObject.Release(transform); transform = null; length = 0; 

                // создать преобразование режима
                transform = mode.CreateEncryption(key, PaddingMode.None); transform.Init();
            }
            // сгенерировать ключевую информацию
            private void Update(int deriveSize)
            {
                // проверить достаточность данных
                if (length >= deriveSize + blockSize) return;
                
                // определить дополнительный размер данных
                int dataLength = (deriveSize + blockSize) - length; 

                // выравняить размер на границу блока
                dataLength = (dataLength + blockSize - 1) / blockSize * blockSize; 

                // изменить размер буфера
                Array.Resize(ref encrypted, length + dataLength); 

                // создать буфер нулевых данных
                byte[] buffer = new byte[dataLength]; 

                // зашифровать данные
                transform.Update(buffer, 0, dataLength, encrypted, length); length += dataLength;
            }
	        // завершить преобразование
	        public void Finish()
            {
                // обнулить сгенерированные ключи
                for (int i = 0; i < encrypted.Length; i++) encrypted[i] = 0; 

                // освободить ресурсы
                RefObject.Release(transform); transform = null; 
            }
	        // наследовать ключ
	        public override ISecretKey DeriveKey(ISecretKey key, 
                byte[] iv, SecretKeyFactory keyFactory, int deriveSize) 
            {
                // указать размер генерируемого ключа
                if (deriveSize < 0) deriveSize = 32; 

                // сбросить старые данные
                if (length > 0) { length -= deriveSize + blockSize; 

                    // сместить буфер
                    Array.Copy(encrypted, deriveSize + blockSize, encrypted, 0, length); 
                }
                // выделить память для ключа
                byte[] derivedKey = new byte[deriveSize]; Update(deriveSize);

                // скопировать ключ
                Array.Copy(encrypted, 0, derivedKey, 0, deriveSize); 

                // вернуть созданный ключ
                return keyFactory.Create(derivedKey); 
            }
            // дополнительный ключ
            public byte[] GetXorK1(int deriveSize) 
            {  
                // выделить память для блока
                byte[] block = new byte[blockSize]; 

                // скопировать блок
                Array.Copy(encrypted, deriveSize, block, 0, blockSize); return block; 
            }
        }
    }
}
