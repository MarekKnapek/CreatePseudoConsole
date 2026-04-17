#include "mk_clib.hpp"

#define mk_lang_jumbo_want 1
#include "mk_sl_time.h"


void mk_clib_fill_date_time(char* const buf, int const cap, int* const len)
{
	mk_sl_time_timestamp_t time_stamp;

	mk_sl_time_timestamp_get_now(&time_stamp);
	*len = mk_sl_time_to_text(&time_stamp, buf, cap);
}
