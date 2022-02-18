using System;
using System.Security; 
using System.Security.Permissions; 
using System.Runtime.Serialization; 

namespace Aladdin.Net
{
    ///////////////////////////////////////////////////////////////////////////
    // Сериализуемое исключение
    ///////////////////////////////////////////////////////////////////////////
    [Serializable]
    public class SerialException : ApplicationException
    {
#if (NET40_OR_GREATER || NETSTANDARD || NETCOREAPP)
        // состояние исключения
        [NonSerialized] private State state = new State();
        
        // конструктор
        private SerialException(string message, string stackTrace) : base(message)
        { 
            // сохранить переданные параметры            
            state.StackTrace = stackTrace; 

            // указать способ сохранения объекта
            SerializeObjectState += delegate(
                object exception, SafeSerializationEventArgs eventArgs)
            {
                // указать состояние объекта
                eventArgs.AddSerializedState(state);
            };
        } 
        // стековый фрейм исключения
        public override string StackTrace { get { return state.StackTrace; }}

        [Serializable]
        private struct State : ISafeSerializationData
        {
            // стековый фрейм исключения
            public string StackTrace; 

            // завершить десериализацию
            public void CompleteDeserialization(object obj)
            {
                // восстановить состояние
                ((SerialException)obj).state = this;
            }
        }
#else
        // конструктор
        protected SerialException(SerializationInfo info, StreamingContext context)

            // выполнить десериализацию
            : base(info, context) { stackTrace = info.GetString("stackTrace"); }

        // конструктор
        private SerialException(string message, string stackTrace) : base(message)

            // сохранить переданные параметры            
            { this.stackTrace = stackTrace; } private string stackTrace;

        // стековый фрейм исключения
        public override string StackTrace { get { return stackTrace; } }

        // сериализовать данные
        [SecuritySafeCritical]
        [SecurityPermission(SecurityAction.LinkDemand, SerializationFormatter = true)]
        public override void GetObjectData(SerializationInfo info, StreamingContext context)
        {
            // сохранить стековый фрейм исключения
            base.GetObjectData(info, context); info.AddValue("stackTrace", stackTrace);
        }
#endif 
        // закодировать исключение
        public static string ToString(Exception exception, bool escape)
        {
            // получить описание ошибки и стековый фрейм
            string message = exception.Message; string stackTrace = exception.StackTrace; 

            // объединить описание ошибки и стековый фрейм
            if (!escape) return String.Format("{0}\0{1}", message, stackTrace); 

            // заменить символы перевода строки
            message    = message   .Replace(Environment.NewLine, "\n"); 
            stackTrace = stackTrace.Replace(Environment.NewLine, "\n"); 

            // выполнить экранирование
            message    = message   .Replace("\\", "\\\\").Replace("\n", "\\n");
            stackTrace = stackTrace.Replace("\\", "\\\\").Replace("\n", "\\n"); 

            // объединить описание ошибки и стековый фрейм
            return String.Format("{0}\n{1}", message, stackTrace); 
        }
        // раскодировать исключение
        public static Exception FromString(string description)
        {
            // найти разделитель строк
            int index = description.IndexOf('\0'); if (index >= 0)
            {
                // извлечь описание ошибки
                string message = description.Substring(0, index); 

                // извлечь стековый фрейм
                string stackTrace = description.Substring(index + 1); 

                // вернуть исключение
                return new SerialException(message, stackTrace);
            }
            // найти разделитель строк
            index = description.IndexOf('\n'); if (index >= 0)
            {
                // извлечь описание ошибки
                string message = description.Substring(0, index); 

                // извлечь стековый фрейм
                string stackTrace = description.Substring(index + 1); 
                
                // отменить экранирование
                message    = message   .Replace("\\n", "\n").Replace("\\\\", "\\");
                stackTrace = stackTrace.Replace("\\n", "\n").Replace("\\\\", "\\");

                // изменить символы перевода строки
                message    = message   .Replace("\n", Environment.NewLine); 
                stackTrace = stackTrace.Replace("\n", Environment.NewLine); 

                // вернуть исключение
                return new SerialException(message, stackTrace);
            }
            // вернуть исключение
            return new SerialException(description, String.Empty);
        }
    }
}
