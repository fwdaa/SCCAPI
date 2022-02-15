using System;
using System.IO;

namespace Aladdin.ISO7816.BER
{
    ///////////////////////////////////////////////////////////////////////////
    // Исходные данные доступа (0x44)
    ///////////////////////////////////////////////////////////////////////////
    public class InitialAccessData : DataObject
    {
        // конструктор
        public InitialAccessData(byte[] content) 
            
            // сохранить переданные параметры
            : base(Authority.ISO7816, ISO7816.Tag.InitialAccessData, content)
        {
            // вернуть значение команды
            if (content.Length >= 5) { Command = new ISO7816.Command(content); } 

            // в зависимости от размера
            else if (content.Length == 1)
            {
                // указать команду READ BINARY
                Command = new ISO7816.Command(0x00, INS.ReadBinary, 0x00, 0x00, content, 0); 
            }
            // в зависимости от размера
            else if (content.Length == 2 && (content[0] & 0x80) != 0)
            {
                // указать команду READ BINARY
                Command = new ISO7816.Command(0x00, INS.ReadBinary, content[0], 0x00, new byte[] { content[1] }, 0); 
            }
            // в зависимости от размера
            else if (content.Length == 2 && (content[0] & 0x80) == 0)
            {
                // вычилить значение параметра P2
                byte P2 = (byte)(((content[0] & 0x1F) << 3) | 0x6); 

                // указать команду READ RECORD(S)
                Command = new ISO7816.Command(0x00, INS.ReadRecords, 0x01, P2, new byte[] { content[1] }, 0); 
            }
            // при ошибке выбросить исключение
            else throw new InvalidDataException(); 
        }
        // значение объекта
        public readonly ISO7816.Command Command; 
    }
}
