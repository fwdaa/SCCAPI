using System;
using System.ComponentModel;

namespace Aladdin.Remoting
{
    ///////////////////////////////////////////////////////////////////////////////
    // Обработчик событий BackgroundWorker
    ///////////////////////////////////////////////////////////////////////////////
    public interface IBackgroundHandler 
    {
        // обработка уведомлений о прогрессе 
        void OnProgressChanged(object sender, ProgressChangedEventArgs e); 
        // обработка уведомления о завершении
        void OnCompleted(object sender, RunWorkerCompletedEventArgs e); 
    }
}
