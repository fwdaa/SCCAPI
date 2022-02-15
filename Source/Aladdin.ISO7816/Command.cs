using System; 
using System.IO; 

namespace Aladdin.ISO7816
{
    ///////////////////////////////////////////////////////////////////////////
    // Команда APDU
    ///////////////////////////////////////////////////////////////////////////
    public class Command
    {
        // класс и код команды 
        public readonly byte CLA; public readonly byte INS; 
        // параметры команды
        public readonly byte P1; public readonly byte P2; 

        // данные команды и ожидаемый размер ответа
        public readonly byte[] Data; public readonly int Ne; 

        // конструктор
        public Command(byte cla, byte ins, byte p1, byte p2)

            // сохранить переданные параметры
            : this(cla, ins, p1, p2, new byte[0], 0) {}

        // конструктор
        public Command(byte cla, byte ins, byte p1, byte p2, byte[] data)

            // сохранить переданные параметры
            : this(cla, ins, p1, p2, data, 0) {}

        // конструктор
        public Command(byte cla, byte ins, byte p1, byte p2, byte[] data, int ne) 
        {
            // проверить наличие данных
            if (data == null) data = new byte[0]; 

            // проверить корректность данных
            if (data.Length > 0xFFFF || ne > 0x10000) throw new ArgumentException(); 

            // сохранить переданные параметры
            CLA = cla; INS = ins; P1 = p1; P2 = p2; Data = data; Ne = ne; 

            // в зависимости от размеров
            if (data.Length <= 255 && ne <= 256)
            {
                // проверить наличие данных в запросе или ответе
                if (data.Length == 0 && ne == 0) encoded = new byte[4 + data.Length];

                // при наличии данных в запросе
                else if (data.Length != 0 && ne == 0) 
                { 
                    // указать размер данных в запросе
                    encoded = new byte[5 + data.Length]; encoded[4] = (byte)data.Length; 

                    // скопировать данные
                    Array.Copy(data, 0, encoded, 5, data.Length); 
                }
                // при наличии данных в ответе
                else if (data.Length == 0 && ne != 0) 
                { 
                    // выделить память для представления
                    encoded = new byte[5 + data.Length]; 

                    // указать максимальный размер данных в ответе
                    encoded[encoded.Length - 1] = (byte)(ne % 256); 
                }
                // выделить память для представления
                else { encoded = new byte[6 + data.Length]; 

                    // указать размер данных в запросе
                    encoded[4] = (byte)data.Length; 

                    // скопировать данные
                    Array.Copy(data, 0, encoded, 5, data.Length); 

                    // указать максимальный размер данных в ответе
                    encoded[encoded.Length - 1] = (byte)(ne % 256); 
                }
            }
            else { 
                // при наличии данных в запросе
                if (data.Length != 0 && ne == 0) 
                { 
                    // выделить память для представления
                    encoded = new byte[7 + data.Length]; encoded[4] = 0x00; 

                    // указать размер данных в запросе
                    encoded[5] = (byte)(data.Length >> 8); encoded[6] = (byte)(data.Length & 0xFF); 

                    // скопировать данные
                    Array.Copy(data, 0, encoded, 7, data.Length); 
                }
                // при наличии данных в ответе
                else if (data.Length == 0 && ne != 0) 
                { 
                    // выделить память для представления
                    encoded = new byte[7 + data.Length]; encoded[4] = 0x00; 

                    // указать максимальный размер данных в ответе
                    encoded[encoded.Length - 2] = (byte)(ne >>   8); 
                    encoded[encoded.Length - 1] = (byte)(ne & 0xFF); 
                }
                else { 
                    // выделить память для представления
                    encoded = new byte[9 + data.Length]; encoded[4] = 0x00; 

                    // указать размер данных в запросе
                    encoded[5] = (byte)(data.Length >> 8); encoded[6] = (byte)(data.Length & 0xFF); 

                    // скопировать данные
                    Array.Copy(data, 0, encoded, 7, data.Length); 

                    // указать максимальный размер данных в ответе
                    encoded[encoded.Length - 2] = (byte)(ne >>   8); 
                    encoded[encoded.Length - 1] = (byte)(ne & 0xFF); 
                }
            }
            // установить заголовок команды
            encoded[0] = cla; encoded[1] = ins; encoded[2] = p1; encoded[3] = p2; 
        }
        // раскодировать команду
        public Command(byte[] encoded) 
        {
            // проверить размер команды
            if (encoded.Length < 4) throw new InvalidDataException(); this.encoded = encoded; 

            // извлечь заголовок команды
            CLA = encoded[0]; INS = encoded[1]; P1 = encoded[2]; P2 = encoded[3];

            // проверить наличие данных или размера
            if (encoded.Length == 4) { Data = new byte[0]; Ne = 0; return; }
            if (encoded.Length == 5) { Data = new byte[0]; 
                
                // извлечь максимальный размер данных в ответе
                Ne = (encoded[4] == 0) ? 256 : encoded[4]; return; 
            }
            // для короткого формата
            if (encoded[4] != 0x00) {

                // при отсутствии размера ответа
                if (5 + encoded[4] == encoded.Length) { Ne = 0; 
                
                    // скопировать данные
                    Data = new byte[encoded[4]]; Array.Copy(encoded, 5, Data, 0, Data.Length); 
                }
                // при наличии размера ответа
                else if (6 + encoded[4] == encoded.Length) 
                { 
                    // скопировать данные
                    Data = new byte[encoded[4]]; Array.Copy(encoded, 5, Data, 0, Data.Length); 

                    // извлечь максимальный размер данных в ответе
                    Ne = (encoded[encoded.Length - 1] == 0) ? 256 : encoded[encoded.Length - 1];
                }
                // при ошибке выбросить исключение
                else throw new InvalidDataException(); 
            }
            else { 
                // проверить корректность данных
                if (encoded.Length == 6) throw new InvalidDataException();

                // при отсутствии данных
                if (encoded.Length == 7) { Data = new byte[0];
                
                    // извлечь максимальный размер данных в ответе
                    Ne = (encoded[encoded.Length - 2] << 8) | encoded[encoded.Length - 1]; 
                    
                    // скорректировать максимальный размер данных
                    if (Ne == 0x0000) Ne = 0x10000; 
                }
                else { 
                    // извлечь размер данных в запросе
                    int length = (encoded[5] << 8) | encoded[6]; 

                    // при отсутствии размера ответа
                    if (7 + length == encoded.Length) { Ne = 0;
                    
                        // скопировать данные
                        Data = new byte[length]; Array.Copy(encoded, 7, Data, 0, Data.Length);
                    }
                    // при наличии размера ответа
                    else if (9 + length == encoded.Length)
                    { 
                        // извлечь максимальный размер данных в ответе
                        Ne = (encoded[encoded.Length - 2] << 8) | encoded[encoded.Length - 1]; 
                    
                        // выделить буфер для данных
                        Data = new byte[length]; if (Ne == 0x0000) Ne = 0x10000; 

                        // скопировать данные
                        Array.Copy(encoded, 7, Data, 0, Data.Length); 
                    }
                    // при ошибке выбросить исключение
                    else throw new InvalidDataException(); 
                }
            }
        }
        // закодированное представление
        public byte[] Encoded { get { return encoded; }} private byte[] encoded; 

        // признак наличия длинных размеров
        public bool IsLong { get { return encoded.Length >= 7 && encoded[4] == 0x00; }} 
    }
}
