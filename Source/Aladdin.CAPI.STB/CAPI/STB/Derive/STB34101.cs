using System; 

///////////////////////////////////////////////////////////////////////////////
// Алгоритм диверсификации ключа
///////////////////////////////////////////////////////////////////////////////
namespace Aladdin.CAPI.STB.Derive
{
    public class STB34101 : KeyDerive
    {
        // алгоритм шифрования блока и уровень ключа
        private CAPI.Cipher belt; private byte[] D;
    
        // конструктор
        public STB34101(CAPI.Cipher belt, byte[] D)
        {
            // сохранить переданные параметры
            this.belt = RefObject.AddRef(belt); this.D = D; 
        
            // проверить корректность параметров
            if (D.Length != 12) throw new ArgumentException(); 
        }
        // освободить используемые ресурсы
        protected override void OnDispose() 
        {
            // освободить используемые ресурсы
            RefObject.Release(belt); base.OnDispose();
        }
        // тип ключа
        public override SecretKeyFactory KeyFactory { get { return belt.KeyFactory; }} 
        // размер используемых ключей
        public override int[] KeySizes { get { return belt.KeySizes; }}

        public override ISecretKey DeriveKey(ISecretKey key, 
            byte[] random, SecretKeyFactory keyFactory, int deriveSize) 
        {
            // получить значение ключа
            byte[] value = key.Value; if (value == null) throw new InvalidKeyException(); 
        
            // указать размер генерируемого ключа
            if (deriveSize < 0) deriveSize = value.Length; 

            // проверить размер ключа
            if (deriveSize > value.Length) throw new NotSupportedException();  

            // проверить размер случайных данных
            if (random != null && random.Length != 16) throw new ArgumentException(); 
        
            // указать заголовок ключа
            byte[] I = (random != null) ? random : new byte[16]; 

            // скопировать уровень ключа
            byte[] data = new byte[64]; Array.Copy(D, 0, data, 4, 12);
        
            // скопировать заголовок ключа
            Array.Copy(I, 0, data, 16, 16);

            switch (value.Length)
            {
            case 16: 
                switch (deriveSize)
                {
                case 16: 
                    // указать фиксированное значение
                    data[0] = (byte)0xB1; data[1] = (byte)0x94; 
                    data[2] = (byte)0xBA; data[3] = (byte)0xC8; break; 
                
                // при ошибке выбросить исключение
                default: throw new NotSupportedException(); 
                }
                // выполнить расширение ключа
                Array.Copy(value, 0, data, 32, 16);
                Array.Copy(value, 0, data, 48, 16); break; 
            
            case 24: 
                switch (deriveSize)
                {
                case 16: 
                    // указать фиксированное значение
                    data[0] = (byte)0x5B; data[1] = (byte)0xE3; 
                    data[2] = (byte)0xD6; data[3] = (byte)0x12; break; 
                
                case 24: 
                    // указать фиксированное значение
                    data[0] = (byte)0x5C; data[1] = (byte)0xB0; 
                    data[2] = (byte)0xC0; data[3] = (byte)0xFF; break; 
                
                // при ошибке выбросить исключение
                default: throw new NotSupportedException(); 
                }
                // скопировать ключ
                Array.Copy(value, 0, data, 32, 24); for (int i = 0; i < 4; i++)
                {
                    // выполнить расширение ключа
                    data[56 + i] = (byte)(value[i +  0] ^ value[i +  4] ^ value[i +  8]); 
                    data[60 + i] = (byte)(value[i + 12] ^ value[i + 16] ^ value[i + 20]); 
                }
                break; 
            
            case 32: 
                switch (deriveSize)
                {
                case 16: 
                    // указать фиксированное значение
                    data[0] = (byte)0xE1; data[1] = (byte)0x2B; 
                    data[2] = (byte)0xDC; data[3] = (byte)0x1A; break; 
                
                case 24: 
                    // указать фиксированное значение
                    data[0] = (byte)0xC1; data[1] = (byte)0xAB; 
                    data[2] = (byte)0x76; data[3] = (byte)0x38; break; 
                
                case 32: 
                    // указать фиксированное значение
                    data[0] = (byte)0xF3; data[1] = (byte)0x3C; 
                    data[2] = (byte)0x65; data[3] = (byte)0x7B; break; 
                
                // при ошибке выбросить исключение
                default: throw new NotSupportedException(); 
                }
                // скопировать ключ
                Array.Copy(value, 0, data, 32, 32); break;
            
            // при ошибке выбросить исключение
            default: throw new InvalidKeyException();
            }
		    // скопировать входные данные
		    byte[] theta = new byte[32]; Array.Copy(data, 0, theta, 0, 32); 

		    // выделить память для переменных
		    byte[] theta1 = new byte[32]; byte[] theta2 = new byte[32]; 

		    // выполнить преобразование
		    for (int i = 0; i < 16; i++) theta1[i] = (byte)(data[32 + i] ^ data[48 + i]);

            // указать ключ для шифрования
            using (ISecretKey thetaKey = belt.KeyFactory.Create(theta))
            { 
                // зашифровать блок
                belt.Encrypt(thetaKey, PaddingMode.None, theta1, 0, 16, theta2, 0);
            }
		    // выполнить преобразование
		    for (int i = 0; i < 16; i++)
		    {
			    theta1[i] ^= theta2[i]; theta2[i] = (byte)(theta1[i] ^ 0xFFFFFFFF); 
		    }
		    // скопировать данные
		    Array.Copy(data, 48, theta1, 16, 16); Array.Copy(data, 32, theta2, 16, 16); 

            // указать ключ для шифрования
            using (ISecretKey theta1Key = belt.KeyFactory.Create(theta1))
            { 
	            // зашифровать блок
	            belt.Encrypt(theta1Key, PaddingMode.None, data, 0, 16, theta, 0); 
            }
		    // выполнить преобразование
		    for (int i = 0; i < 16; i++) theta[i] ^= data[i];

            // указать ключ для шифрования
            using (ISecretKey theta2Key = belt.KeyFactory.Create(theta2))
            { 
                // зашифровать блок
	            belt.Encrypt(theta2Key, PaddingMode.None, data, 16, 16, theta, 16); 
            }
		    // выполнить преобразование
		    for (int i = 0; i < 16; i++) theta[i + 16] ^= data[16 + i];
        
            // вернуть новый ключ
            return keyFactory.Create(Arrays.CopyOf(theta, 0, deriveSize)); 
        }
	    ///////////////////////////////////////////////////////////////////////////
	    // Тесты известного ответа
	    ///////////////////////////////////////////////////////////////////////////
        public static void Test1(KeyDerive keyDerive) 
        {
            KnownTest(keyDerive, new byte[] {
                (byte)0xE9, (byte)0xDE, (byte)0xE7, (byte)0x2C, 
                (byte)0x8F, (byte)0x0C, (byte)0x0F, (byte)0xA6, 
                (byte)0x2D, (byte)0xDB, (byte)0x49, (byte)0xF4, 
                (byte)0x6F, (byte)0x73, (byte)0x96, (byte)0x47, 
                (byte)0x06, (byte)0x07, (byte)0x53, (byte)0x16, 
                (byte)0xED, (byte)0x24, (byte)0x7A, (byte)0x37, 
                (byte)0x39, (byte)0xCB, (byte)0xA3, (byte)0x83, 
                (byte)0x03, (byte)0xA9, (byte)0x8B, (byte)0xF6
            }, new byte[] {
                (byte)0x5B, (byte)0xE3, (byte)0xD6, (byte)0x12, 
                (byte)0x17, (byte)0xB9, (byte)0x61, (byte)0x81, 
                (byte)0xFE, (byte)0x67, (byte)0x86, (byte)0xAD, 
                (byte)0x71, (byte)0x6B, (byte)0x89, (byte)0x0B
            }, new byte[] {
                (byte)0x6B, (byte)0xBB, (byte)0xC2, (byte)0x33, 
                (byte)0x66, (byte)0x70, (byte)0xD3, (byte)0x1A, 
                (byte)0xB8, (byte)0x3D, (byte)0xAA, (byte)0x90, 
                (byte)0xD5, (byte)0x2C, (byte)0x05, (byte)0x41
            }); 
            KnownTest(keyDerive, new byte[] {
                (byte)0xE9, (byte)0xDE, (byte)0xE7, (byte)0x2C, 
                (byte)0x8F, (byte)0x0C, (byte)0x0F, (byte)0xA6, 
                (byte)0x2D, (byte)0xDB, (byte)0x49, (byte)0xF4, 
                (byte)0x6F, (byte)0x73, (byte)0x96, (byte)0x47, 
                (byte)0x06, (byte)0x07, (byte)0x53, (byte)0x16, 
                (byte)0xED, (byte)0x24, (byte)0x7A, (byte)0x37, 
                (byte)0x39, (byte)0xCB, (byte)0xA3, (byte)0x83, 
                (byte)0x03, (byte)0xA9, (byte)0x8B, (byte)0xF6
            }, new byte[] {
                (byte)0x5B, (byte)0xE3, (byte)0xD6, (byte)0x12, 
                (byte)0x17, (byte)0xB9, (byte)0x61, (byte)0x81, 
                (byte)0xFE, (byte)0x67, (byte)0x86, (byte)0xAD, 
                (byte)0x71, (byte)0x6B, (byte)0x89, (byte)0x0B
            }, new byte[] {
                (byte)0x9A, (byte)0x25, (byte)0x32, (byte)0xA1, 
                (byte)0x8C, (byte)0xBA, (byte)0xF1, (byte)0x45, 
                (byte)0x39, (byte)0x8D, (byte)0x5A, (byte)0x95, 
                (byte)0xFE, (byte)0xEA, (byte)0x6C, (byte)0x82, 
                (byte)0x5B, (byte)0x9C, (byte)0x19, (byte)0x71, 
                (byte)0x56, (byte)0xA0, (byte)0x02, (byte)0x75
            }); 
            KnownTest(keyDerive, new byte[] {
                (byte)0xE9, (byte)0xDE, (byte)0xE7, (byte)0x2C, 
                (byte)0x8F, (byte)0x0C, (byte)0x0F, (byte)0xA6, 
                (byte)0x2D, (byte)0xDB, (byte)0x49, (byte)0xF4, 
                (byte)0x6F, (byte)0x73, (byte)0x96, (byte)0x47, 
                (byte)0x06, (byte)0x07, (byte)0x53, (byte)0x16, 
                (byte)0xED, (byte)0x24, (byte)0x7A, (byte)0x37, 
                (byte)0x39, (byte)0xCB, (byte)0xA3, (byte)0x83, 
                (byte)0x03, (byte)0xA9, (byte)0x8B, (byte)0xF6
            }, new byte[] {
                (byte)0x5B, (byte)0xE3, (byte)0xD6, (byte)0x12, 
                (byte)0x17, (byte)0xB9, (byte)0x61, (byte)0x81, 
                (byte)0xFE, (byte)0x67, (byte)0x86, (byte)0xAD, 
                (byte)0x71, (byte)0x6B, (byte)0x89, (byte)0x0B
            }, new byte[] {
                (byte)0x76, (byte)0xE1, (byte)0x66, (byte)0xE6, 
                (byte)0xAB, (byte)0x21, (byte)0x25, (byte)0x6B, 
                (byte)0x67, (byte)0x39, (byte)0x39, (byte)0x7B, 
                (byte)0x67, (byte)0x2B, (byte)0x87, (byte)0x96, 
                (byte)0x14, (byte)0xB8, (byte)0x1C, (byte)0xF0, 
                (byte)0x59, (byte)0x55, (byte)0xFC, (byte)0x3A, 
                (byte)0xB0, (byte)0x93, (byte)0x43, (byte)0xA7, 
                (byte)0x45, (byte)0xC4, (byte)0x8F, (byte)0x77
            }); 
        }
    }
}
