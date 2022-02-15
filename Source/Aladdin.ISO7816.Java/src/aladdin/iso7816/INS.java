package aladdin.iso7816;

///////////////////////////////////////////////////////////////////////////////
// Коды команд
///////////////////////////////////////////////////////////////////////////////
public abstract class INS 
{
	public static final byte BERTLV                                 = (byte)0x01;
	public static final byte DEACTIVATE_FILE                        = (byte)0x04;
	public static final byte DEACTIVATE_RECORD                      = (byte)0x06;
	public static final byte ACTIVATE_RECORD                        = (byte)0x08;
	public static final byte ERASE_RECORDS                          = (byte)0x0C;
	public static final byte ERASE_BINARY                           = (byte)0x0E;
	public static final byte ERASE_BINARY_BERTLV                    = (byte)0x0F;
	public static final byte PERFORM_SCQL_OPERATION                 = (byte)0x10;
	public static final byte PERFORM_TRANSACTION_OPERATION          = (byte)0x12;
	public static final byte PERFORM_USER_OPERATION                 = (byte)0x14;
	public static final byte VERIFY                                 = (byte)0x20;
	public static final byte VERIFY_BERTLV                          = (byte)0x21;
	public static final byte MANAGE_SECURITY_ENVIRONMENT            = (byte)0x22;
	public static final byte CHANGE_REFERENCE_DATA                  = (byte)0x24;
	public static final byte CHANGE_REFERENCE_DATA_BERTLV           = (byte)0x25;
	public static final byte DISABLE_VERIFICATION_REQUIREMENT       = (byte)0x26;
	public static final byte ENABLE_VERIFICATION_REQUIREMENT        = (byte)0x28;
	public static final byte PERFORM_SECURITY_OPERATION             = (byte)0x2A;
	public static final byte PERFORM_SECURITY_OPERATION_BERTLV      = (byte)0x2B;
	public static final byte RESET_RETRY_COUNTER                    = (byte)0x2C;
	public static final byte RESET_RETRY_COUNTER_BERTLV             = (byte)0x2D;
	public static final byte PERFORM_BIOMETRIC_OPERATION            = (byte)0x2E;
	public static final byte PERFORM_BIOMETRIC_OPERATION_BERTLV     = (byte)0x2F;
	public static final byte COMPARE_BERTLV                         = (byte)0x33;
	public static final byte GET_ATTRIBUTE                          = (byte)0x34;
	public static final byte GET_ATTRIBUTE_BERTLV                   = (byte)0x35;
	public static final byte APPLICATION_MANAGEMENT_REQUEST         = (byte)0x40;
	public static final byte APPLICATION_MANAGEMENT_REQUEST_BERTLV  = (byte)0x41;
	public static final byte ACTIVATE_FILE                          = (byte)0x44;
	public static final byte GENERATE_ASYMMETRIC_KEY_PAIR           = (byte)0x46;
	public static final byte GENERATE_ASYMMETRIC_KEY_PAIR_BERTLV    = (byte)0x47;
	public static final byte MANAGE_CHANNEL                         = (byte)0x70;
	public static final byte EXTERNAL_AUTHENTICATE                  = (byte)0x82;
	public static final byte GET_CHALLENGE                          = (byte)0x84;
	public static final byte GENERAL_AUTHENTICATE                   = (byte)0x86;
	public static final byte GENERAL_AUTHENTICATE_BERTLV            = (byte)0x87;
	public static final byte INTERNAL_AUTHENTICATE                  = (byte)0x88;
	public static final byte SEARCH_BINARY                          = (byte)0xA0;
	public static final byte SEARCH_BINARY_BERTLV                   = (byte)0xA1;
	public static final byte SEARCH_RECORD                          = (byte)0xA2;
	public static final byte SELECT                                 = (byte)0xA4;
	public static final byte SELECT_DATA_BERTLV                     = (byte)0xA5;
	public static final byte READ_BINARY                            = (byte)0xB0;
	public static final byte READ_BINARY_BERTLV                     = (byte)0xB1;
	public static final byte READ_RECORDS                           = (byte)0xB2;
	public static final byte READ_RECORDS_BERTLV                    = (byte)0xB3;
	public static final byte GET_RESPONSE                           = (byte)0xC0;
	public static final byte ENVELOPE                               = (byte)0xC2;
	public static final byte ENVELOPE_BERTLV                        = (byte)0xC3;
	public static final byte GET_DATA                               = (byte)0xCA;
	public static final byte GET_DATA_BERTLV                        = (byte)0xCB;
	public static final byte GET_NEXT_DATA                          = (byte)0xCC;
	public static final byte GET_NEXT_DATA_BERTLV                   = (byte)0xCD;
	public static final byte MANAGE_DATA_BERTLV                     = (byte)0xCF;
	public static final byte WRITE_BINARY                           = (byte)0xD0;
	public static final byte WRITE_BINARY_BERTLV                    = (byte)0xD1;
	public static final byte WRITE_RECORD                           = (byte)0xD2;
	public static final byte UPDATE_BINARY                          = (byte)0xD6;
	public static final byte UPDATE_BINARY_BERTLV                   = (byte)0xD7;
	public static final byte PUT_NEXT_DATA                          = (byte)0xD8;
	public static final byte PUT_NEXT_DATA_BERTLV                   = (byte)0xD9;
	public static final byte PUT_DATA                               = (byte)0xDA;
	public static final byte PUT_DATA_BERTLV                        = (byte)0xDB;
	public static final byte UPDATE_RECORD                          = (byte)0xDC;
	public static final byte UPDATE_RECORD_BERTLV                   = (byte)0xDD;
	public static final byte UPDATE_DATA                            = (byte)0xDE;
	public static final byte UPDATE_DATA_BERTLV                     = (byte)0xDF;
	public static final byte CREATE_FILE                            = (byte)0xE0;
	public static final byte APPEND_RECORD                          = (byte)0xE2;
	public static final byte DELETE_FILE                            = (byte)0xE4;
	public static final byte TERMINATE_DF                           = (byte)0xE6;
	public static final byte TERMINATE_EF                           = (byte)0xE8;
	public static final byte LOAD_APPLICATION                       = (byte)0xEA;
	public static final byte LOAD_APPLICATION_BERTLV                = (byte)0xEB;
	public static final byte DELETE_DATA                            = (byte)0xEE;
	public static final byte REMOVE_APPLICATION                     = (byte)0xEC;
	public static final byte REMOVE_APPLICATION_BERTLV              = (byte)0xED;
	public static final byte TERMINATE_CARD_USAGE                   = (byte)0xFE;
}
