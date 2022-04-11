using System; 

namespace Aladdin.CAPI
{
    ///////////////////////////////////////////////////////////////////////////////
    // Режим блочного алгоритма шифрования
    ///////////////////////////////////////////////////////////////////////////////
    public abstract class BlockMode : Cipher
    {
	    // конструктор
	    protected BlockMode(PaddingMode padding)
    
		    // сохранить переданные параметры
		    { this.padding = padding; } private PaddingMode padding;
    
        // получить режим дополнения
	    protected PaddingMode Padding { get { return padding; }}
        
        // алгоритм зашифрования данных
	    public override Transform CreateEncryption(ISecretKey key, PaddingMode padding) 
	    {
            // указать режим дополнения
            if (this.padding != PaddingMode.Any) padding = this.padding; 
        
            // сохранить способ дополнения
            PaddingMode oldPadding = this.padding; this.padding = padding;
            try { 
                // получить режим зашифрования 
                using (Transform encryption = CreateEncryption(key))
                {
                    // указать требуемое дополнение
                    return GetPadding().CreateEncryption(encryption, Mode); 
                }
            }
            // восстановить способ дополнения
            finally { this.padding = oldPadding; }
        }
	    // алгоритм расшифрования данных
	    public override Transform CreateDecryption(ISecretKey key, PaddingMode padding) 
	    {
            // указать режим дополнения
            if (this.padding != PaddingMode.Any) padding = this.padding; 
        
            // сохранить способ дополнения
            PaddingMode oldPadding = this.padding; this.padding = padding;
            try { 
                // получить режим расшифрования 
                using (Transform decryption = CreateDecryption(key))
                {
                    // указать требуемое дополнение
                    return GetPadding().CreateDecryption(decryption, Mode); 
                }
            }
            // восстановить способ дополнения
            finally { this.padding = oldPadding; }
        }
        // указать режим дополнения
	    protected virtual BlockPadding GetPadding() 
	    {
            // вернуть отсутствие дополнения
            if (padding == PaddingMode.None) return new Pad.None();
        
            // вернуть дополнение нулями
            if (padding == PaddingMode.Zero) return new Pad.Zero();

            // вернуть дополнение PKCS
            if (padding == PaddingMode.PKCS5) return new Pad.PKCS5(); 

            // вернуть дополнение ISO
            if (padding == PaddingMode.ISO) return new Pad.ISO(); 

            // для режима дополнения CTS
            if (padding == PaddingMode.CTS) return new Pad.CTS(); 

            // при ошибке выбросить исключение
            throw new NotSupportedException();
        }
        ///////////////////////////////////////////////////////////////////////////
        // Изменение режима дополнения (исходный режим должен быть Any или None)
        ///////////////////////////////////////////////////////////////////////////
        public class PaddingConverter : BlockMode
        {
            // режим шифрования 
            private Cipher cipher; 
        
            // конструктор
            public PaddingConverter(Cipher cipher, PaddingMode padding) : base(padding)
            {
                // сохранить переданные параметры
                this.cipher = RefObject.AddRef(cipher); 
            } 
            // деструктор
            protected override void OnDispose() 
            { 
                // освободить выделенные ресурсы
                RefObject.Release(cipher); base.OnDispose();
            } 
            // тип ключа
            public override SecretKeyFactory KeyFactory  { get { return cipher.KeyFactory; }}

            // размер блока
            public override int BlockSize { get { return cipher.BlockSize; }}
    
            // режим алгоритма
            public override CipherMode Mode { get { return cipher.Mode; }}

            // алгоритм зашифрования данных
            protected override Transform CreateEncryption(ISecretKey key) 
            {
                // алгоритм зашифрования данных
                return cipher.CreateEncryption(key, PaddingMode.None); 
            }
            // алгоритм расшифрования данных
            protected override Transform CreateDecryption(ISecretKey key) 
            {
                // алгоритм расшифрования данных
                return cipher.CreateDecryption(key, PaddingMode.None); 
            }
        }
    };
}
