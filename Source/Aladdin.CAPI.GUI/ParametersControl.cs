using System; 
using System.Windows.Forms;

namespace Aladdin.CAPI.GUI
{
	///////////////////////////////////////////////////////////////////////////
	// Графический элемент выбора параметров ключа
	///////////////////////////////////////////////////////////////////////////
	public class ParametersControl : UserControl	
	{
		// получить параметры ключа
        public virtual IParameters GetParameters() { return null; } 
	}
}
