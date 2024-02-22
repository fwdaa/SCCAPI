#include "stdafx.h"
#include "stsnist.h"
#include "cprob.h"  

////////////////////////////////////////////////////////////////////////////////////
// 2.1 Frequency (Monobit) Test 
// https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-22r1a.pdf
////////////////////////////////////////////////////////////////////////////////////
bool FrequencyTest(const BitSequence* epsilon, size_t n)
{
	// выполнить 2.1.4.1
	int s_n = 0; for (size_t i = 0; i < n; i++) s_n += (epsilon[i] ? 1 : -1);
	
	// выполнить 2.1.4.2
	double s_obs = fabs((double)s_n) / sqrt((double)n);

	// выполнить 2.1.4.3
	double p_value = erfc(s_obs / sqrt(2.0));

	// выполнить 2.1.5
	return (p_value >= 0.01); 
}
