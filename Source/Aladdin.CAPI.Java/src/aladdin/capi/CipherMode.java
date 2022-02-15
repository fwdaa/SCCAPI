package aladdin.capi;

///////////////////////////////////////////////////////////////////////////
// Режимы шифрования
///////////////////////////////////////////////////////////////////////////
public abstract class CipherMode 
{ 
    // размер блока
    public int blockSize() { return -1; }
    
    // вывести параметры алгоритмов
    public abstract void dump(); 
        
    // режим ECB
    public static class ECB extends CipherMode 
    {
        // вывести параметры алгоритмов
        @Override public void dump()
        {
            // указать режим алгоритма
            Test.println("Mode = ECB");
        }
    }
    // режим CBC
    public static class CBC extends CipherMode
    {
        // синхропосылка и размер блока 
        private final byte[] iv; private final int blockSize; 
        
        // конструктор
        public CBC(byte[] iv) { this(iv, iv.length); }
        
        // конструктор
        public CBC(byte[] iv, int blockSize) 
        { 
            // проверить корректность данных
            if (iv.length < blockSize) throw new IllegalArgumentException(); 

            // сохранить переданные параметры
            this.iv = iv; this.blockSize = blockSize; 
        } 
        // размер блока
        @Override public final int blockSize() { return blockSize; }

        // синхропосылка
        public final byte[] iv() { return iv; } 

        // вывести параметры алгоритмов
        @Override public void dump()
        {
            // указать режим алгоритма
            Test.println("Mode = CBC");
            
            // указать размер блока
            Test.println("BlockSize = %1$s", blockSize);
            
            // указать синхропосылку
            Test.dump("IV", iv); 
        }
    }
    // режим CFB
    public static class CFB extends CipherMode
    {
        // синхропосылка и размер блока 
        private final byte[] iv; private final int blockSize; 
        
        // конструктор
        public CFB(byte[] iv, int blockSize) 
        { 
            // проверить корректность данных
            if (iv.length < blockSize) throw new IllegalArgumentException(); 
            
            // сохранить переданные параметры
            this.iv = iv; this.blockSize = blockSize; 
        }
        // размер блока
        @Override public final int blockSize() { return blockSize; }
        
        // синхропосылка
        public final byte[] iv() { return iv; }

        // вывести параметры алгоритмов
        @Override public void dump()
        {
            // указать режим алгоритма
            Test.println("Mode = CFB");

            // указать размер блока
            Test.println("BlockSize = %1$s", blockSize);
            
            // указать синхропосылку
            Test.dump("IV", iv); 
        }
    }
    // режим OFB
    public static class OFB extends CipherMode
    {
        // синхропосылка и размер блока
        private final byte[] iv; private final int blockSize; 
        
        // конструктор
        public OFB(byte[] iv, int blockSize) 
        { 
            // проверить корректность данных
            if (iv.length < blockSize) throw new IllegalArgumentException(); 
            
            // сохранить переданные параметры
            this.iv = iv; this.blockSize = blockSize; 
        }
        // размер блока
        @Override public final int blockSize() { return blockSize; }
        
        // синхропосылка
        public final byte[] iv() { return iv; }

        // вывести параметры алгоритмов
        @Override public void dump()
        {
            // указать режим алгоритма
            Test.println("Mode = OFB");

            // указать размер блока
            Test.println("BlockSize = %1$s", blockSize);
            
            // указать синхропосылку
            Test.dump("IV", iv); 
        }
    }
    // режим CTR
    public static class CTR extends CipherMode
    {
        // синхропосылка и размер счетчика
        private final byte[] iv; private final int counterSize; 
        // размер блока
        private final int blockSize; 
        
        // конструктор
        public CTR(byte[] iv, int counterSize, int blockSize) 
        { 
            // сохранить переданные параметры
            this.iv = iv; this.counterSize = counterSize; this.blockSize = blockSize; 
        }
        // конструктор
        public CTR(byte[] iv, int blockSize) 
        { 
            // сохранить переданные параметры
            this.iv = iv; this.counterSize = iv.length; this.blockSize = blockSize; 
        }
        // размер счетчика
        public final int counterSize() { return counterSize; }
        // размер блока
        @Override public final int blockSize() { return blockSize; }
        
        // синхропосылка
        public final byte[] iv() { return iv; }

        // вывести параметры алгоритмов
        @Override public void dump()
        {
            // указать режим алгоритма
            Test.println("Mode = CTR, CounterSize = %1$s", counterSize);

            // указать размер блока
            Test.println("BlockSize = %1$s", blockSize);
            
            // указать синхропосылку
            Test.dump("IV", iv); 
        }
    }
}
