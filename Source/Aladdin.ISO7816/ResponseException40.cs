using System; 
using System.Security; 
using System.Security.Permissions; 
using System.Runtime.Serialization; 
using System.IO; 

namespace Aladdin.ISO7816
{
    ///////////////////////////////////////////////////////////////////////////
    // Ошибка выполнения APDU-команды
    ///////////////////////////////////////////////////////////////////////////
    [Serializable]
    public partial class ResponseException : IOException
    {
        // состояние исключения
        [NonSerialized] private State state = new State();
        
        // конструктор
        public ResponseException(ushort sw) { state.SW = sw; 

            // указать способ сохранения объекта
            SerializeObjectState += delegate(
                object exception, SafeSerializationEventArgs eventArgs)
            {
                // указать состояние объекта
                eventArgs.AddSerializedState(state);
            };
        } 
        // статус завершения
        public ushort SW { get { return state.SW; }}

        [Serializable]
        private struct State : ISafeSerializationData
        {
            // статус завершения
            public ushort SW; 

            // завершить десериализацию
            public void CompleteDeserialization(object obj)
            {
                // восстановить состояние
                ((ResponseException)obj).state = this;
            }
        }
    }
}
