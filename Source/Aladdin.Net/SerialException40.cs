using System;
using System.Runtime.Serialization; 

namespace Aladdin.Net
{
    ///////////////////////////////////////////////////////////////////////////
    // Сериализуемое исключение
    ///////////////////////////////////////////////////////////////////////////
    [Serializable]
    public partial class SerialException : ApplicationException
    {
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
    }
}
