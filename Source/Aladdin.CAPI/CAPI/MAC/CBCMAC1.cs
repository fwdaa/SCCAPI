using System;

namespace Aladdin.CAPI.MAC
{
    ///////////////////////////////////////////////////////////////////////////////
    // Алгоритм вычисления имитовставки CBC-MAC (тип 1)
    ///////////////////////////////////////////////////////////////////////////////
    public class CBCMAC1 : BlockMac
    {
        // блочный алгоритм шифрования и способ дополнения блока
        private Cipher modeCBC; private PaddingMode padding; 

        // преобразования шифрования и размер имитовставки
        private Transform encryption; private int macSize; 
    
	    // конструктор
	    public CBCMAC1(Cipher modeCBC, PaddingMode padding, int macSize)
        { 
            // проверить корректность параметров
            if (macSize > modeCBC.BlockSize) throw new ArgumentException();

            // сохранить переданные параметры
            this.modeCBC = RefObject.AddRef(modeCBC); 
            
            // сохранить переданные параметры
            this.padding = padding; this.macSize = macSize;
        }
        // освободить выделенные ресурсы
        protected override void OnDispose()
        { 
            // освободить выделенные ресурсы
            RefObject.Release(modeCBC); RefObject.Release(encryption); base.OnDispose();
        } 
	    // размер хэш-значения в байтах
	    public override int MacSize { get { return macSize; }}
	
        // тип ключа
        public override SecretKeyFactory KeyFactory { get { return modeCBC.KeyFactory; }} 
	    // размер ключей
	    public override int[] KeySizes { get { return modeCBC.KeySizes; }}
	    // размер блока в байтах
	    public override int BlockSize { get { return modeCBC.BlockSize; }}

	    // инициализировать алгоритм
	    public override void Init(ISecretKey key) 
        {
            // создать преобразование зашифрования
            base.Init(key); encryption = modeCBC.CreateEncryption(key, PaddingMode.None); encryption.Init();
        }
	    // обработать блок данных
	    protected override void Update(byte[] data, int dataOff)
        {
            // выделить блок для преобразования
            byte[] mac = new byte[modeCBC.BlockSize]; 

            // выполнить преобразование
            encryption.Update(data, dataOff, BlockSize, mac, 0); 
        }
	    // завершить преобразование
	    protected override void Finish(
            byte[] data, int dataOff, int dataLen, byte[] buf, int bufOff)
        {
            // выделить блок для преобразования
            byte[] mac = new byte[modeCBC.BlockSize]; 

            // при отсутствии дополнения
            if (padding == PaddingMode.None)
            { 
                // выполнить преобразование
                encryption.Finish(data, dataOff, dataLen, mac, 0);
            }
            else { 
                // создать дополнительный блок
                byte[] block = new byte[mac.Length]; 
                
                // при кратном числе блоков                
                if ((dataLen % block.Length) == 0) { block[0] = 0x80; 
                
                    // выполнить преобразование
                    if (dataLen > 0) encryption.Update(data, dataOff, dataLen, mac, 0);
                }
                else { block[dataLen] = 0x80; 

                    // скопировать неполный блок
                    Array.Copy(data, dataOff, block, 0, dataLen); 
                }
                // выполнить преобразование
                encryption.Finish(block, 0, block.Length, mac, 0);
            }
            // скопировать вычисленную имитовставку
            Array.Copy(mac, 0, buf, bufOff, macSize);

            // освободить выделенные ресурсы
            RefObject.Release(encryption); encryption = null; 
        }
    }
}
