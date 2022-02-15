using System; 
using System.Windows.Forms;

namespace Aladdin.CAPI.GUI
{
	///////////////////////////////////////////////////////////////////////////
	// ������ ������ ���������� �����
	///////////////////////////////////////////////////////////////////////////
	public partial class ParametersDialog : Form
	{
        // ������� ��������� �����
        public static IParameters Show(IWin32Window parent, ParametersControl control)
        {
            // ������� ������
            ParametersDialog dialog = new ParametersDialog(control); 

            // ���������� ������
            DialogResult result = Aladdin.GUI.ModalView.Show(parent, dialog); 

			// ��������� ��������� �������
			return (result == DialogResult.OK) ? dialog.Parameters : null;
        }
		// �����������
		public ParametersDialog(ParametersControl control) 
        { 
            // ��������� ���������� ���������
            InitializeComponent(); this.control = control; 
        }
		// �����������
		public ParametersDialog() { InitializeComponent(); } 
        
        // ��������� ��������� �����
        public IParameters Parameters { get { return parameters; } }   

        // ������� ���������� � ��������� ���������
        private ParametersControl control; private IParameters parameters;

		///////////////////////////////////////////////////////////////////////
		// ������� 
		///////////////////////////////////////////////////////////////////////
		private void OnLoad(object sender, System.EventArgs e)
		{
			// ������� ��������� �������� ����������
			control.Padding = panel.Padding; control.Size = panel.Size;	 

			// ������� ��������� �������� ����������
            control.Location = panel.Location; Controls.Add(control); 
		}
        private void OnSelect(object sender, EventArgs e)
        {
			// ������� ��������� �����
			parameters = control.GetParameters(); 
        }
	}
}
