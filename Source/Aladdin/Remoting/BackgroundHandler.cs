using System;
using System.ComponentModel;

namespace Aladdin.Remoting
{
    ///////////////////////////////////////////////////////////////////////////////
    // Обработчик событий BackgroundWorker
    ///////////////////////////////////////////////////////////////////////////////
    public sealed class BackgroundHandler : IBackgroundHandler
    {
        // обработчики событий
        private readonly RunWorkerCompletedEventHandler onCompleted; 
        private readonly ProgressChangedEventHandler    onProgressChanged;

        // конструктор
        public BackgroundHandler(RunWorkerCompletedEventHandler onCompleted, 
            ProgressChangedEventHandler onProgressChanged)
        {
            // сохранить переданные параметры
            this.onCompleted = onCompleted; this.onProgressChanged = onProgressChanged; 
        }
        // обработка уведомлений о прогрессе 
        public void OnProgressChanged(object sender, ProgressChangedEventArgs e)
        {
            // обработать событие
            if (onProgressChanged != null) onProgressChanged(sender, e); 
        }
        // обработка уведомления о завершении
        public void OnCompleted(object sender, RunWorkerCompletedEventArgs e)
        {
            // обработать событие
            if (onCompleted != null) onCompleted(sender, e); 
        }
    }
}
