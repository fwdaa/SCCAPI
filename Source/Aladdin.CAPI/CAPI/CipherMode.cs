using System; 

namespace Aladdin.CAPI
{
    ///////////////////////////////////////////////////////////////////////////
    // Режимы шифрования
    ///////////////////////////////////////////////////////////////////////////
    public abstract class CipherMode 
    { 
        // размер блока
        public virtual int BlockSize { get { return -1; }}

        // вывести параметры алгоритмов
        public abstract void Dump(); 

        ///////////////////////////////////////////////////////////////////////
        // Режим ECB
        ///////////////////////////////////////////////////////////////////////
        public class ECB : CipherMode 
        {
            // вывести параметры алгоритмов
            public override void Dump()
            {
                // указать режим алгоритма
                Test.WriteLine("Mode = ECB");
            }
        }
        ///////////////////////////////////////////////////////////////////////
        // Режим CBC
        ///////////////////////////////////////////////////////////////////////
        public class CBC : CipherMode
        {
            // синхропосылка и размер сдвига
            private byte[] iv; private int blockSize; 

            // конструктор
            public CBC(byte[] iv) : this(iv, iv.Length) {}

            // конструктор
            public CBC(byte[] iv, int blockSize) 
            { 
                // проверить корректность данных
                if (iv.Length < blockSize) throw new ArgumentException(); 

                // сохранить переданные параметры
                this.iv = iv; this.blockSize = blockSize; 
            } 
            // размер блока
            public override int BlockSize { get { return blockSize; }}
            // синхропосылка
            public byte[] IV { get { return iv; }} 

            // вывести параметры алгоритмов
            public override void Dump()
            {
                // указать режим алгоритма
                Test.WriteLine("Mode = CBC");
            
                // указать размер блока
                Test.WriteLine("BlockSize = {0}", blockSize);
            
                // указать синхропосылку
                Test.Dump("IV", iv); 
            }
        }
        ///////////////////////////////////////////////////////////////////////
        // Режим CFB
        ///////////////////////////////////////////////////////////////////////
        public class CFB : CipherMode
        {
            // синхропосылка и размер сдвига
            private byte[] iv; private int blockSize; 
        
            // конструктор
            public CFB(byte[] iv, int blockSize) 
            { 
                // проверить корректность данных
                if (iv.Length < blockSize) throw new ArgumentException(); 

                // сохранить переданные параметры
                this.iv = iv; this.blockSize = blockSize; 
            }
            // размер блока
            public override int BlockSize { get { return blockSize; }}
            // синхропосылка
            public byte[] IV { get { return iv; }}

            // вывести параметры алгоритмов
            public override void Dump()
            {
                // указать режим алгоритма
                Test.WriteLine("Mode = CFB");
            
                // указать размер блока
                Test.WriteLine("BlockSize = {0}", blockSize);
            
                // указать синхропосылку
                Test.Dump("IV", iv); 
            }
        }
        ///////////////////////////////////////////////////////////////////////
        // Режим OFB
        ///////////////////////////////////////////////////////////////////////
        public class OFB : CipherMode
        {
            // синхропосылка и размер блока
            private byte[] iv; private int blockSize; 
        
            // конструктор
            public OFB(byte[] iv, int blockSize) 
            { 
                // проверить корректность данных
                if (iv.Length < blockSize) throw new ArgumentException(); 

                // сохранить переданные параметры
                this.iv = iv; this.blockSize  = blockSize; 
            }
            // размер блока
            public override int BlockSize { get { return blockSize; }}
            // синхропосылка
            public byte[] IV { get { return iv; }}

            // вывести параметры алгоритмов
            public override void Dump()
            {
                // указать режим алгоритма
                Test.WriteLine("Mode = OFB");
            
                // указать размер блока
                Test.WriteLine("BlockSize = {0}", blockSize);
            
                // указать синхропосылку
                Test.Dump("IV", iv); 
            }
        }
        ///////////////////////////////////////////////////////////////////////
        // Режим CTR
        ///////////////////////////////////////////////////////////////////////
        public class CTR : CipherMode
        {
            // синхропосылка, размер счетчика и размер блока
            private byte[] iv; private int counterSize; private int blockSize; 
        
            // конструктор
            public CTR(byte[] iv, int counterSize, int blockSize) 
            { 
                // сохранить переданные параметры
                this.iv = iv; this.counterSize = counterSize; this.blockSize  = blockSize; 
            }
            // конструктор
            public CTR(byte[] iv, int blockSize) 
            { 
                // сохранить переданные параметры
                this.iv = iv; this.counterSize = iv.Length; this.blockSize  = blockSize; 
            }
            // синхропосылка
            public byte[] IV { get { return iv; }}
            // размер счетчика
            public int CounterSize { get { return counterSize; }}
            // размер блока
            public override int BlockSize { get { return blockSize; }}

            // вывести параметры алгоритмов
            public override void Dump()
            {
                // указать режим алгоритма
                Test.WriteLine("Mode = CTR, CounterSize = {0}", counterSize);
            
                // указать размер блока
                Test.WriteLine("BlockSize = {0}", blockSize);
            
                // указать синхропосылку
                Test.Dump("IV", iv); 
            }
        }
    }
}
