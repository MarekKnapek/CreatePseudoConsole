#include "mk_clib.hpp"

#pragma warning(push, 0)
#include <Windows.h>
#pragma warning(pop)

#pragma warning(push, 0)
#include <assert.h>
#include <string.h>
#pragma warning(pop)

#define mk_min(a, b) ((((b)) < ((a))) ? ((b)) : ((a)))
#define mk_max(a, b) ((((b)) < ((a))) ? ((a)) : ((b)))
#define mk_countof(p_x) ((int)(sizeof(((p_x))) / sizeof(((p_x))[0])))
#define mk_strlit(x) x, (mk_countof(x) - 1)
#define mk_check(p_x) do{ if(!((p_x))){ DWORD gle_private; gle_private = GetLastError(); (void)gle_private; __debugbreak(); ExitProcess(__LINE__); } }while(false)
#define mk_check_todo() mk_check(false)

/*
─ ━ │ ┃ ┄ ┅ ┆ ┇ ┈ ┉ ┊ ┋ ┌ ┍ ┎ ┏
┐ ┑ ┒ ┓ └ ┕ ┖ ┗ ┘ ┙ ┚ ┛ ├ ┝ ┞ ┟
┠ ┡ ┢ ┣ ┤ ┥ ┦ ┧ ┨ ┩ ┪ ┫ ┬ ┭ ┮ ┯
┰ ┱ ┲ ┳ ┴ ┵ ┶ ┷ ┸ ┹ ┺ ┻ ┼ ┽ ┾ ┿
╀ ╁ ╂ ╃ ╄ ╅ ╆ ╇ ╈ ╉ ╊ ╋ ╌ ╍ ╎ ╏
═ ║ ╒ ╓ ╔ ╕ ╖ ╗ ╘ ╙ ╚ ╛ ╜ ╝ ╞ ╟
╠ ╡ ╢ ╣ ╤ ╥ ╦ ╧ ╨ ╩ ╪ ╫ ╬ ╭ ╮ ╯
╰ ╱ ╲ ╳ ╴ ╵ ╶ ╷ ╸ ╹ ╺ ╻ ╼ ╽ ╾ ╿

▀	▁	▂	▃	▄	▅	▆	▇	█	▉	▊	▋	▌	▍	▎	▏
▐	░	▒	▓	▔	▕	▖	▗	▘	▙	▚	▛	▜	▝	▞	▟
*/

/* ========== handles ========== */
#pragma warning(push, 0)
#include <winternl.h>
#pragma warning(pop)

typedef NTSTATUS(NTAPI*fnNtQuerySystemInformation)
(
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	OUT PVOID SystemInformation,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength OPTIONAL
);
typedef NTSTATUS(NTAPI*fnNtQueryObject)
(
	_In_opt_ HANDLE Handle,
	_In_ OBJECT_INFORMATION_CLASS ObjectInformationClass,
	_Out_writes_bytes_opt_(ObjectInformationLength) PVOID ObjectInformation,
	_In_ ULONG ObjectInformationLength,
	_Out_opt_ PULONG ReturnLength
);

typedef struct
{
	ULONG ProcessId;
	BYTE ObjectTypeNumber;
	BYTE Flags;
	USHORT Handle;
	PVOID Object;
	ACCESS_MASK GrantedAccess;
}xxx_SYSTEM_HANDLE;

typedef struct
{
	ULONG HandleCount;
	xxx_SYSTEM_HANDLE Handles[1];
}xxx_SYSTEM_HANDLE_INFORMATION;

typedef enum
{
	NonPagedPool,
	PagedPool,
	NonPagedPoolMustSucceed,
	DontUseThisType,
	NonPagedPoolCacheAligned,
	PagedPoolCacheAligned,
	NonPagedPoolCacheAlignedMustS
}xxx_POOL_TYPE;

typedef struct
{
	UNICODE_STRING Name;
	ULONG TotalNumberOfObjects;
	ULONG TotalNumberOfHandles;
	ULONG TotalPagedPoolUsage;
	ULONG TotalNonPagedPoolUsage;
	ULONG TotalNamePoolUsage;
	ULONG TotalHandleTableUsage;
	ULONG HighWaterNumberOfObjects;
	ULONG HighWaterNumberOfHandles;
	ULONG HighWaterPagedPoolUsage;
	ULONG HighWaterNonPagedPoolUsage;
	ULONG HighWaterNamePoolUsage;
	ULONG HighWaterHandleTableUsage;
	ULONG InvalidAttributes;
	GENERIC_MAPPING GenericMapping;
	ULONG ValidAccess;
	BOOLEAN SecurityRequired;
	BOOLEAN MaintainHandleCount;
	USHORT MaintainTypeList;
	xxx_POOL_TYPE PoolType;
	ULONG PagedPoolUsage;
	ULONG NonPagedPoolUsage;
}xxx_OBJECT_TYPE_INFORMATION;

static void mk_close_dead_process_handles()
{
	DWORD pid;
	PCWCHAR process;
	HMODULE ntdll;
	fnNtQuerySystemInformation pfnNtQuerySystemInformation;
	fnNtQueryObject pfnNtQueryObject;
	ULONG cap;
	xxx_SYSTEM_HANDLE_INFORMATION* infos;
	NTSTATUS st;
	ULONG len;
	ULONG n;
	ULONG i;
	HANDLE handle;
	SIZE_T info[(4 * 1024) / sizeof(SIZE_T)];
	xxx_OBJECT_TYPE_INFORMATION* pinfo;
	DWORD dw;
	BOOL b;

	pid = GetCurrentProcessId();
	process = L"Process";
	ntdll = GetModuleHandleA("ntdll"); mk_check(ntdll);
	pfnNtQuerySystemInformation = (fnNtQuerySystemInformation)GetProcAddress(ntdll, "NtQuerySystemInformation"); mk_check(pfnNtQuerySystemInformation);
	pfnNtQueryObject = (fnNtQueryObject)GetProcAddress(ntdll, "NtQueryObject"); mk_check(pfnNtQueryObject);
	cap = 1 * 1024 * 1024;
	infos = (xxx_SYSTEM_HANDLE_INFORMATION*)HeapAlloc(GetProcessHeap(), 0, cap); mk_check(infos);
	for(;;)
	{
		st = pfnNtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)16/*SystemHandleInformation*/, infos, cap, &len);
		if(st != 0xc0000004/*STATUS_INFO_LENGTH_MISMATCH*/)
		{
			mk_check(st == 0);
			break;
		}
		cap *= 2;
		infos = (xxx_SYSTEM_HANDLE_INFORMATION*)HeapReAlloc(GetProcessHeap(), 0, infos, cap); mk_check(infos);
	}
	n = infos->HandleCount;
	for(i = 0; i != n; ++i)
	{
		if(infos->Handles[i].ProcessId == (ULONG)pid)
		{
			handle = (HANDLE)(UINT_PTR)infos->Handles[i].Handle;
			st = pfnNtQueryObject(handle, ObjectTypeInformation, &info[0], sizeof(info), &len);
			if(st == 0)
			{
				pinfo = (xxx_OBJECT_TYPE_INFORMATION*)&info;
				if(pinfo->Name.Length == wcslen(process) * sizeof(wchar_t) && memcmp(pinfo->Name.Buffer, process, wcslen(process) * sizeof(wchar_t)) == 0)
				{
					dw = WaitForSingleObject(handle, 0);
					if(dw == WAIT_OBJECT_0)
					{
						b = CloseHandle(handle); mk_check(b);
					}
				}
			}
		}
	}
	b = HeapFree(GetProcessHeap(), 0, infos); mk_check(b);
}
/* ========== handles ========== */

struct turbo_app_child_s
{
	CRITICAL_SECTION m_cs;
	CONDITION_VARIABLE m_cv;
	HANDLE m_pipe_input_write;
	HANDLE m_pipe_output_read;
	HANDLE m_pseudo_console;
	HANDLE m_thread;
	HANDLE m_process;
	HANDLE* m_event;
	COORD m_size;
	COORD m_cursor_pos;
	WORD m_default_attrs;
	bool m_cursor_visible;
	int m_input_len;
	unsigned char m_input_buf[64 * 1024];
	wchar_t m_chars[0xff * 0xff];
	WORD m_attrs[0xff * 0xff];
};
typedef struct turbo_app_child_s turbo_app_child_t;

static void turbo_app_rw_child_rw_construct(turbo_app_child_t* const child, HANDLE const pipe_input_write, HANDLE const pipe_output_read, COORD const size, HANDLE const pseudo_console)
{
	assert(child);
	assert(pipe_input_write);
	assert(pipe_output_read);
	assert(&size);
	assert(pseudo_console);

	InitializeCriticalSection(&child->m_cs);
	InitializeConditionVariable(&child->m_cv);
	child->m_pipe_input_write = pipe_input_write;
	child->m_pipe_output_read = pipe_output_read;
	child->m_pseudo_console = pseudo_console;
	(void)child->m_thread;
	(void)child->m_process;
	(void)child->m_event;
	child->m_size = size;
	child->m_cursor_pos.Y = 0; child->m_cursor_pos.X = 0;
	child->m_default_attrs = (FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE) | (0);
	child->m_cursor_visible = true;
	child->m_input_len = 0;
	(void)child->m_input_buf;
	(void)child->m_chars;
	(void)child->m_attrs;
}

static void turbo_app_rw_child_rw_destroy(turbo_app_child_t* const child)
{
	BOOL b;

	assert(child);

	DeleteCriticalSection(&child->m_cs);
	(void)child->m_cv;
	b = CloseHandle(child->m_pipe_input_write); mk_check(b);
	b = CloseHandle(child->m_pipe_output_read); mk_check(b);
	(void)child->m_pseudo_console;
	b = CloseHandle(child->m_thread); mk_check(b);
	/*b = CloseHandle(child->m_process); mk_check(b);*/ /* ========== handles ========== */
	(void)child->m_event;
	(void)child->m_size;
	(void)child->m_cursor_pos;
	(void)child->m_default_attrs;
	(void)child->m_cursor_visible;
	(void)child->m_input_len;
	(void)child->m_input_buf;
	(void)child->m_chars;
	(void)child->m_attrs;
}

static bool turbo_app_rw_child_ro_is_ded(turbo_app_child_t const* const child)
{
	bool is;

	assert(child);

	is = child->m_pseudo_console == NULL;
	return is;
}

static void turbo_app_rw_child_rw_read(turbo_app_child_t* const child)
{
	unsigned char buf[4 * 1024];
	BOOL b;
	DWORD read;
	DWORD gle;
	bool done;

	assert(child);

	for(;;)
	{
		EnterCriticalSection(&child->m_cs);
		for(;;)
		{
			if(mk_countof(child->m_input_buf) - child->m_input_len < mk_countof(buf))
			{
				b = SleepConditionVariableCS(&child->m_cv, &child->m_cs, INFINITE); mk_check(b);
			}
			else
			{
				break;
			}
		}
		LeaveCriticalSection(&child->m_cs);
		b = ReadFile(child->m_pipe_output_read, &buf[0], mk_countof(buf), &read, NULL); mk_check(b || ((gle = GetLastError()) == ERROR_BROKEN_PIPE));
		done = b == FALSE || read == 0; if(!b){ read = 0; }
		EnterCriticalSection(&child->m_cs);
		memcpy(&child->m_input_buf[child->m_input_len], &buf[0], read);
		child->m_input_len += read;
		LeaveCriticalSection(&child->m_cs);
		b = SetEvent(*child->m_event); mk_check(b);
		if(done)
		{
			break;
		}
	}
}

static DWORD __stdcall turbo_app_rw_child_rw_thread_proc(LPVOID const arg)
{
	turbo_app_child_t* child;

	assert(arg);

	child = ((turbo_app_child_t*)(arg));
	turbo_app_rw_child_rw_read(child);
	return 0;
}

struct turbo_app_s
{
	HANDLE m_screen_buffer;
	HANDLE m_std_input;
	HANDLE m_event;
	CONSOLE_SCREEN_BUFFER_INFO m_screen_buffer_info;
	bool m_should_exit;
	wchar_t m_chars[0xff * 0xff];
	WORD m_attrs[0xff * 0xff];
	INPUT_RECORD m_events_buf[1];
	DWORD m_events_cnt;
	int m_active_child_idx;
	turbo_app_child_t* m_children[(MAXIMUM_WAIT_OBJECTS - 2)];
};
typedef struct turbo_app_s turbo_app_t;

static turbo_app_t* pthe_app;

static void turbo_app_rw_child_rw_make(turbo_app_t* const turbo_app, turbo_app_child_t* const child, HANDLE* const pipe_input_read, HANDLE* const pipe_output_write)
{
	COORD size;
	SECURITY_ATTRIBUTES attrs;
	BOOL b;
	HANDLE pipe_input_write;
	HANDLE pipe_output_read;
	HRESULT hr;
	HANDLE pseudo_console;

	assert(turbo_app);
	assert(child);
	assert(pipe_input_read);
	assert(pipe_output_write);

	size.X = 80; size.Y = 25;
	attrs.nLength = sizeof(attrs);
	attrs.lpSecurityDescriptor = NULL;
	attrs.bInheritHandle = FALSE;
	b = CreatePipe(pipe_input_read, &pipe_input_write, &attrs, 0); mk_check(b); mk_check(*pipe_input_read); mk_check(pipe_input_write);
	b = CreatePipe(&pipe_output_read, pipe_output_write, &attrs, 0); mk_check(b); mk_check(pipe_output_read); mk_check(*pipe_output_write);
	hr = CreatePseudoConsole(size, *pipe_input_read, *pipe_output_write, 0, &pseudo_console); mk_check(hr == S_OK); mk_check(pseudo_console);
	turbo_app_rw_child_rw_construct(child, pipe_input_write, pipe_output_read, size, pseudo_console);
	child->m_event = &turbo_app->m_event;
	child->m_thread = CreateThread(NULL, 0, &turbo_app_rw_child_rw_thread_proc, child, 0, NULL); mk_check(child->m_thread);
}

static void turbo_app_rw_construct(turbo_app_t* const turbo_app)
{
	assert(turbo_app);

	turbo_app->m_screen_buffer = NULL;
	turbo_app->m_std_input = NULL;
	turbo_app->m_event = NULL;
	memset(&turbo_app->m_screen_buffer_info, 0x00, sizeof(turbo_app->m_screen_buffer_info));
	turbo_app->m_should_exit = false;
	memset(&turbo_app->m_chars[0], 0x00, sizeof(turbo_app->m_chars));
	memset(&turbo_app->m_attrs[0], 0x00, sizeof(turbo_app->m_attrs));
	memset(&turbo_app->m_events_buf[0], 0x00, sizeof(turbo_app->m_events_buf));
	turbo_app->m_events_cnt = 0;
	turbo_app->m_active_child_idx = -1;
	memset(&turbo_app->m_children[0], 0x00, sizeof(turbo_app->m_children));
}

static void turbo_app_rw_child_rw_kill_and_drain(turbo_app_child_t* child)
{
	DWORD dw;

	assert(child);

	ClosePseudoConsole(child->m_pseudo_console); child->m_pseudo_console = NULL;
	for(;;)
	{
		EnterCriticalSection(&child->m_cs);
		child->m_input_len = 0;
		LeaveCriticalSection(&child->m_cs);
		WakeAllConditionVariable(&child->m_cv);
		dw = WaitForSingleObject(child->m_thread, 10); mk_check(dw == WAIT_OBJECT_0 || dw == WAIT_TIMEOUT);
		if(dw == WAIT_OBJECT_0)
		{
			break;
		}
	}
}

static void turbo_app_rw_clean(turbo_app_t* const turbo_app)
{
	int n;
	int i;
	turbo_app_child_t* child;
	DWORD dw;
	BOOL b;

	assert(turbo_app);

	n = mk_countof(turbo_app->m_children);
	for(i = 0; i != n; ++i)
	{
		child = turbo_app->m_children[i];
		if(child)
		{
			if(!turbo_app_rw_child_ro_is_ded(child))
			{
				turbo_app_rw_child_rw_kill_and_drain(child);
			}
			dw = WaitForSingleObject(child->m_thread, INFINITE); mk_check(dw == WAIT_OBJECT_0);
			turbo_app_rw_child_rw_destroy(child);
			b = HeapFree(GetProcessHeap(), 0, child); mk_check(b);
		}
	}
}

static void turbo_app_rw_destroy(turbo_app_t* const turbo_app)
{
	BOOL b;

	assert(turbo_app);

	turbo_app_rw_clean(turbo_app);

	(void)turbo_app->m_screen_buffer;
	(void)turbo_app->m_std_input;
	b = CloseHandle(turbo_app->m_event); mk_check(b);
	(void)turbo_app->m_screen_buffer_info;
	(void)turbo_app->m_should_exit;
	(void)turbo_app->m_chars;
	(void)turbo_app->m_attrs;
	(void)turbo_app->m_events_buf;
	(void)turbo_app->m_events_cnt;
	(void)turbo_app->m_active_child_idx;
	(void)turbo_app->m_children;
}

static void turbo_app_rw_draw_clear(turbo_app_t* const turbo_app)
{
	int height;
	int width;
	int n;
	int y;
	int x;
	int idx;

	assert(turbo_app);

	height = turbo_app->m_screen_buffer_info.dwSize.Y; height = mk_min(height, 0xff);
	width = turbo_app->m_screen_buffer_info.dwSize.X; width = mk_min(width, 0xff);
	n = height * width;
	for(y = 0; y != height; ++y)
	{
		for(x = 0; x != width; ++x)
		{
			idx = y * width + x;
			turbo_app->m_chars[idx] = L' ';
			turbo_app->m_attrs[idx] = (FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE) | (0);
		}
	}
}

static void turbo_app_rw_draw_border(turbo_app_t* const turbo_app)
{
	int height;
	int width;
	int n;
	int y;
	int x;
	int idx;

	assert(turbo_app);

	height = turbo_app->m_screen_buffer_info.dwSize.Y; height = mk_min(height, 0xff);
	width = turbo_app->m_screen_buffer_info.dwSize.X; width = mk_min(width, 0xff);
	n = height * width;
	for(y = 0; y != height; ++y)
	{
		for(x = 0; x != width; ++x)
		{
			idx = y * width + x;
			if(y == 0 && x == 0)                      { turbo_app->m_chars[idx] = L'╔'; }
			else if(y == 0 && x == width - 1)         { turbo_app->m_chars[idx] = L'╗'; }
			else if(y == height - 1 && x == 0)        { turbo_app->m_chars[idx] = L'╚'; }
			else if(y == height - 1 && x == width - 1){ turbo_app->m_chars[idx] = L'╝'; }
			else if(y == 0 || y == height - 1)        { turbo_app->m_chars[idx] = L'═'; }
			else if(x == 0 || x == width - 1)         { turbo_app->m_chars[idx] = L'║'; }
		}
	}
}

static void turbo_app_rw_draw_bitblt(turbo_app_t* const turbo_app)
{
	COORD pos;
	int height;
	int width;
	int n;
	BOOL b;
	DWORD written;

	assert(turbo_app);

	pos.X = 0; pos.Y = 0;
	height = turbo_app->m_screen_buffer_info.dwSize.Y; height = mk_min(height, 0xff);
	width = turbo_app->m_screen_buffer_info.dwSize.X; width = mk_min(width, 0xff);
	n = height * width;
	b = WriteConsoleOutputCharacterW(turbo_app->m_screen_buffer, &turbo_app->m_chars[0], n, pos, &written); mk_check(b); /*mk_check(written == (DWORD)n);*/
	b = WriteConsoleOutputAttribute(turbo_app->m_screen_buffer, &turbo_app->m_attrs[0], n, pos, &written); mk_check(b); /*mk_check(written == (DWORD)n);*/
}

static void turbo_app_rw_draw_clock(turbo_app_t* const turbo_app)
{
	char txt[32];
	int len;
	int height;
	int width;
	int row;
	int col;
	int off;
	int n;
	int i;
	int idx;

	mk_clib_fill_date_time(&txt[0], mk_countof(txt), &len); mk_check(len >= 1);
	len = mk_min(len, 19);
	height = turbo_app->m_screen_buffer_info.dwSize.Y; height = mk_min(height, 0xff);
	width = turbo_app->m_screen_buffer_info.dwSize.X; width = mk_min(width, 0xff);
	if(width >= len + 6)
	{
		row = height - 1;
		col = width - 1 - 3 - len;
		off = row * width + col;
		n = len;
		for(i = 0; i != n; ++i)
		{
			idx = off + i;
			turbo_app->m_chars[idx] = (wchar_t)txt[i];
		}
	}
}

static void turbo_app_rw_draw_rect(turbo_app_t* const turbo_app, int const rect_x, int const rect_y, int const rect_w, int const rect_h)
{
	int offset_y;
	int offset_x;
	int height;
	int width;
	int total;
	int n;
	int i;
	int y;
	int x;
	int idx;

	assert(turbo_app);
	assert(rect_x >= 0);
	assert(rect_y >= 0);
	assert(rect_w >= 0);
	assert(rect_h >= 0);

	offset_x = rect_x;
	offset_y = rect_y;
	height = turbo_app->m_screen_buffer_info.dwSize.Y; height = mk_min(height, 0xff);
	width = turbo_app->m_screen_buffer_info.dwSize.X; width = mk_min(width, 0xff);
	total = height * width;
	y = offset_y;
	x = offset_x + 0;
	idx = y * width + x;
	turbo_app->m_chars[idx] = L'┌';
	n = rect_w;
	for(i = 0; i != n; ++i)
	{
		y = offset_y;
		x = offset_x + 1 + i;
		idx = y * width + x;
		turbo_app->m_chars[idx] = L'─';
		y = offset_y + rect_h + 1;
		x = offset_x + 1 + i;
		idx = y * width + x;
		turbo_app->m_chars[idx] = L'─';
	}
	y = offset_y;
	x = offset_x + 1 + rect_w;
	idx = y * width + x;
	turbo_app->m_chars[idx] = L'┐';
	n = rect_h;
	for(i = 0; i != n; ++i)
	{
		x = offset_x;
		y = offset_y + 1 + i;
		idx = y * width + x;
		turbo_app->m_chars[idx] = L'│';
		x = offset_x + rect_w + 1;
		y = offset_y + 1 + i;
		idx = y * width + x;
		turbo_app->m_chars[idx] = L'│';
	}
	y = offset_y + rect_h + 1;
	x = offset_x;
	idx = y * width + x;
	turbo_app->m_chars[idx] = L'└';
	y = offset_y + rect_h + 1;
	x = offset_x + 1 + rect_w;
	idx = y * width + x;
	turbo_app->m_chars[idx] = L'┘';
}

static void turbo_app_rw_draw_num(turbo_app_t* const turbo_app, int const rect_x, int const rect_y, int const rect_w, int const rect_h)
{
	wchar_t const* const ded = L"dead";

	turbo_app_child_t* child;
	int offset_y;
	int offset_x;
	int height;
	int width;
	int y;
	int x;
	int idx;
	int n;
	int i;

	assert(turbo_app);
	assert(rect_x >= 0);
	assert(rect_y >= 0);
	assert(rect_w >= 0);
	assert(rect_h >= 0);

	(void)rect_w;
	(void)rect_h;
	child = turbo_app->m_children[turbo_app->m_active_child_idx];
	offset_x = rect_x;
	offset_y = rect_y;
	height = turbo_app->m_screen_buffer_info.dwSize.Y; height = mk_min(height, 0xff);
	width = turbo_app->m_screen_buffer_info.dwSize.X; width = mk_min(width, 0xff);
	y = offset_y;
	x = offset_x + 2;
	idx = y * width + x;
	turbo_app->m_chars[idx] = L'0' + (turbo_app->m_active_child_idx % 10); /* todo more digits */
	if(turbo_app_rw_child_ro_is_ded(child))
	{
		n = (int)wcslen(ded);
		for(i = 0; i != n; ++i)
		{
			y = offset_y;
			x = offset_x + 4 + i;
			idx = y * width + x;
			turbo_app->m_chars[idx] = ded[i];
		}
	}
}

static void turbo_app_rw_draw_child_contents(turbo_app_t* const turbo_app, int const offset_x, int const offset_y, turbo_app_child_t* const child)
{
	int p_w;
	int p_h;
	int ch_w;
	int ch_h;
	int ch_y;
	int ch_x;
	int ch_idx;
	int p_x;
	int p_y;
	int p_idx;
	COORD coords;
	BOOL b;
	CONSOLE_CURSOR_INFO cursor;

	assert(turbo_app);
	assert(offset_x || !offset_x);
	assert(offset_y || !offset_y);
	assert(child);

	p_w = turbo_app->m_screen_buffer_info.dwSize.X; p_w = mk_min(p_w, 0xff);
	p_h = turbo_app->m_screen_buffer_info.dwSize.Y; p_h = mk_min(p_h, 0xff);
	ch_w = child->m_size.X; ch_w = mk_min(ch_w, 0xff);
	ch_h = child->m_size.Y; ch_h = mk_min(ch_h, 0xff);
	for(ch_y = 0; ch_y != ch_h; ++ch_y)
	{
		for(ch_x = 0; ch_x != ch_w; ++ch_x)
		{
			ch_idx = ch_y * ch_w + ch_x;
			p_x = offset_x + ch_x;
			p_y = offset_y + ch_y;
			p_idx = p_y * p_w + p_x;
			turbo_app->m_chars[p_idx] = child->m_chars[ch_idx];
			turbo_app->m_attrs[p_idx] = child->m_attrs[ch_idx];
		}
	}
	if(child->m_cursor_visible)
	{
		coords.X = ((SHORT)(offset_x + child->m_cursor_pos.X));
		coords.Y = ((SHORT)(offset_y + child->m_cursor_pos.Y));
		b = SetConsoleCursorPosition(turbo_app->m_screen_buffer, coords); mk_check(b);
		b = GetConsoleCursorInfo(turbo_app->m_screen_buffer, &cursor); mk_check(b);
		cursor.bVisible = TRUE;
		b = SetConsoleCursorInfo(turbo_app->m_screen_buffer, &cursor); mk_check(b);
	}
	else
	{
		b = GetConsoleCursorInfo(turbo_app->m_screen_buffer, &cursor); mk_check(b);
		cursor.bVisible = FALSE;
		b = SetConsoleCursorInfo(turbo_app->m_screen_buffer, &cursor); mk_check(b);
	}
}

static void turbo_app_rw_draw_child(turbo_app_t* const turbo_app, turbo_app_child_t* const child)
{
	assert(turbo_app);
	assert(child);

	turbo_app_rw_draw_rect(turbo_app, 2, 2, child->m_size.X, child->m_size.Y);
	turbo_app_rw_draw_num(turbo_app, 2, 2, child->m_size.X, child->m_size.Y);
	turbo_app_rw_draw_child_contents(turbo_app, 2 + 1, 2 + 1, child);
}

static void turbo_app_rw_hide_cursor(turbo_app_t* const turbo_app)
{
	BOOL b;
	CONSOLE_CURSOR_INFO cursor;

	assert(turbo_app);

	b = GetConsoleCursorInfo(turbo_app->m_screen_buffer, &cursor); mk_check(b);
	cursor.bVisible = FALSE;
	b = SetConsoleCursorInfo(turbo_app->m_screen_buffer, &cursor); mk_check(b);
}

static void turbo_app_rw_draw_active_child(turbo_app_t* const turbo_app)
{
	assert(turbo_app);

	if(turbo_app->m_active_child_idx != -1)
	{
		turbo_app_rw_draw_child(turbo_app, turbo_app->m_children[turbo_app->m_active_child_idx]);
	}
	else
	{
		turbo_app_rw_hide_cursor(turbo_app);
	}
}

static void turbo_app_rw_draw_content(turbo_app_t* const turbo_app)
{
	turbo_app_rw_draw_active_child(turbo_app);
}

static void turbo_app_rw_draw_all(turbo_app_t* const turbo_app)
{
	assert(turbo_app);

	turbo_app_rw_draw_clear(turbo_app);
	turbo_app_rw_draw_content(turbo_app);
	turbo_app_rw_draw_border(turbo_app);
	turbo_app_rw_draw_clock(turbo_app);
	turbo_app_rw_draw_bitblt(turbo_app);
}

static void turbo_app_rw_child_draw_erase(turbo_app_t* const turbo_app, turbo_app_child_t* const child)
{
	int w;
	int h;
	int y;
	int x;
	int idx;

	assert(turbo_app);
	assert(child);

	(void)turbo_app;
	w = child->m_size.X; w = mk_min(w, 0xff);
	h = child->m_size.Y; h = mk_min(h, 0xff);
	for(y = 0; y != h; ++y)
	{
		for(x = 0; x != w; ++x)
		{
			idx = y * w + x;
			child->m_chars[idx] = L' ';
			child->m_attrs[idx] = (FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE) | (0);
		}
	}
}

static void turbo_app_rw_child_on_erase_saved_lines(turbo_app_t* const turbo_app, turbo_app_child_t* const child)
{
	assert(turbo_app);
	assert(child);

	turbo_app_rw_child_draw_erase(turbo_app, child);
}

static void turbo_app_rw_child_on_cmd_reset(turbo_app_t* const turbo_app, turbo_app_child_t* const child)
{
	assert(turbo_app);
	assert(child);

	(void)turbo_app;
	child->m_default_attrs = (FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE) | (0);
}

static bool turbo_app_rw_on_ctrlc_my(turbo_app_t* const turbo_app, DWORD const ctrl_type)
{
	BOOL b;
	bool handled;

	handled = false;
	if
	(
		(ctrl_type == CTRL_C_EVENT) ||
		(ctrl_type == CTRL_BREAK_EVENT) ||
		(ctrl_type == CTRL_CLOSE_EVENT) ||
		(ctrl_type == CTRL_LOGOFF_EVENT) ||
		(ctrl_type == CTRL_SHUTDOWN_EVENT) ||
		(false)
	)
	{
		b = SetEvent(turbo_app->m_event); mk_check(b);
		handled = true;
	}
	return handled;
}

static BOOL __stdcall turbo_app_rw_on_ctrlc_win(DWORD const ctrl_type)
{
	bool handled;
	BOOL b;

	handled = turbo_app_rw_on_ctrlc_my(pthe_app, ctrl_type);
	b = handled ? TRUE : FALSE;
	return b;
}

static void turbo_app_rw_register_ctrlc(turbo_app_t* const turbo_app)
{
	BOOL b;

	assert(turbo_app);

	turbo_app->m_event = CreateEventW(NULL, TRUE, FALSE, NULL); mk_check(turbo_app->m_event);
	b = SetConsoleCtrlHandler(&turbo_app_rw_on_ctrlc_win, TRUE); mk_check(b);
}

static void turbo_app_rw_unregister_ctrlc(turbo_app_t* const turbo_app)
{
	BOOL b;

	assert(turbo_app);

	(void)turbo_app;
	b = SetConsoleCtrlHandler(&turbo_app_rw_on_ctrlc_win, FALSE); mk_check(b);
}

static void turbo_app_rw_screen_enter(turbo_app_t* const turbo_app)
{
	HANDLE screen_buffer;
	BOOL b;
	DWORD cmode;

	assert(turbo_app);

	turbo_app->m_screen_buffer_info.dwSize.X = 0;
	turbo_app->m_screen_buffer_info.dwSize.Y = 0;
	screen_buffer = CreateConsoleScreenBuffer(GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CONSOLE_TEXTMODE_BUFFER, NULL); mk_check(screen_buffer != INVALID_HANDLE_VALUE);
	turbo_app->m_screen_buffer = screen_buffer;
	b = SetConsoleActiveScreenBuffer(turbo_app->m_screen_buffer); mk_check(b);
	b = GetConsoleScreenBufferInfo(turbo_app->m_screen_buffer, &turbo_app->m_screen_buffer_info); mk_check(b);
	b = GetConsoleMode(turbo_app->m_screen_buffer, &cmode); mk_check(b);
	cmode = cmode | ENABLE_WINDOW_INPUT;
	cmode = cmode | ENABLE_MOUSE_INPUT;
	cmode = cmode &~ ENABLE_INSERT_MODE;
	b = SetConsoleMode(turbo_app->m_screen_buffer, cmode); mk_check(b);
}

static void turbo_app_rw_screen_leave(turbo_app_t* const turbo_app)
{
	BOOL b;

	assert(turbo_app);

	b = CloseHandle(turbo_app->m_screen_buffer); mk_check(b);
}

static void turbo_app_rw_run_program(turbo_app_t* const turbo_app, wchar_t const* const app, wchar_t* const cmd)
{
	int n;
	int i;
	int idx;
	turbo_app_child_t* child;
	HANDLE pipe_input_read;
	HANDLE pipe_output_write;
	STARTUPINFOEXW si;
	BOOL b;
	SIZE_T size;
	DWORD gle;
	alignas(16) unsigned char storage[1 * 1024];
	PROCESS_INFORMATION pi;
	DWORD dw;

	assert(turbo_app);
	assert(app);
	assert(cmd);

	n = mk_countof(turbo_app->m_children);
	for(i = 0; i != n; ++i)
	{
		if(!turbo_app->m_children[i])
		{
			break;
		}
	}
	if(i != n)
	{
		idx = i;
		child = (turbo_app_child_t*)HeapAlloc(GetProcessHeap(), 0, sizeof(*child)); mk_check(child);
		turbo_app->m_children[idx] = child;
		turbo_app->m_active_child_idx = idx;
		turbo_app_rw_child_rw_make(turbo_app, child, &pipe_input_read, &pipe_output_write);
		memset(&si, 0x00, sizeof(si));
		si.StartupInfo.cb = sizeof(si);
		b = InitializeProcThreadAttributeList(NULL, 1, 0, &size); mk_check(b == 0 && (gle = GetLastError()) == ERROR_INSUFFICIENT_BUFFER); mk_check(size <= mk_countof(storage));
		si.lpAttributeList = ((LPPROC_THREAD_ATTRIBUTE_LIST)(&storage[0]));
		b = InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &size); mk_check(b);
		b = UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, child->m_pseudo_console, sizeof(child->m_pseudo_console), NULL, NULL); mk_check(b);
		b = CreateProcessW(&app[0], &cmd[0], NULL, NULL, FALSE, CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, &si.StartupInfo, &pi);
		mk_check(b);
		mk_check(pi.hProcess);
		mk_check(pi.hThread);
		child->m_process = pi.hProcess;
		dw = ResumeThread(pi.hThread); (void)dw;
		b = CloseHandle(pi.hThread); mk_check(b);
		b = CloseHandle(pipe_input_read); mk_check(b);
		b = CloseHandle(pipe_output_write); mk_check(b);
	}
}

static void turbo_app_rw_run_self(turbo_app_t* const turbo_app)
{
	HMODULE self;
	DWORD len;
	wchar_t path[32 * 1024];
	wchar_t cmd_line[1 + mk_countof(path) + 1];

	assert(turbo_app);

	self = GetModuleHandleW(NULL); mk_check(self);
	len = GetModuleFileNameW(self, &path[0], mk_countof(path)); mk_check(len != 0); mk_check(len != mk_countof(path));
	cmd_line[0] = L'"';
	memcpy(&cmd_line[1], &path[0], len * sizeof(wchar_t));
	cmd_line[1 + len + 0] = L'"';
	cmd_line[1 + len + 1] = L'\0';
	turbo_app_rw_run_program(turbo_app, &path[0], &cmd_line[0]);
}

static void turbo_app_rw_run_cmd(turbo_app_t* const turbo_app)
{
	wchar_t const* path;
	DWORD len;
	wchar_t cmd_line[1 + (32 * 1024) + 1];

	assert(turbo_app);

	path = L"C:\\Windows\\System32\\cmd.exe";
	len = (DWORD)wcslen(path);
	cmd_line[0] = L'"';
	memcpy(&cmd_line[1], &path[0], len * sizeof(wchar_t));
	cmd_line[1 + len + 0] = L'"';
	cmd_line[1 + len + 1] = L'\0';
	turbo_app_rw_run_program(turbo_app, &path[0], &cmd_line[0]);
}

static void turbo_app_rw_prev(turbo_app_t* const turbo_app)
{
	int old_idx;
	int n;
	int i;
	int new_idx;

	assert(turbo_app);

	old_idx = turbo_app->m_active_child_idx;
	turbo_app->m_active_child_idx = -1;
	n = mk_countof(turbo_app->m_children);
	for(i = 0; i != n; ++i)
	{
		new_idx = (old_idx + n - 1 - i) % n;
		if(turbo_app->m_children[new_idx])
		{
			turbo_app->m_active_child_idx = new_idx;
			break;
		}
	}
}

static void turbo_app_rw_next(turbo_app_t* const turbo_app)
{
	int old_idx;
	int n;
	int i;
	int new_idx;

	assert(turbo_app);

	old_idx = turbo_app->m_active_child_idx;
	turbo_app->m_active_child_idx = -1;
	n = mk_countof(turbo_app->m_children);
	for(i = 0; i != n; ++i)
	{
		new_idx = (old_idx + n + 1 + i) % n;
		if(turbo_app->m_children[new_idx])
		{
			turbo_app->m_active_child_idx = new_idx;
			break;
		}
	}
}

static void turbo_app_rw_reap(turbo_app_t* const turbo_app)
{
	turbo_app_child_t* child;
	DWORD dw;
	BOOL b;
	int idx;

	assert(turbo_app);

	if(turbo_app->m_active_child_idx != -1)
	{
		child = turbo_app->m_children[turbo_app->m_active_child_idx]; assert(child);
		if(turbo_app_rw_child_ro_is_ded(child))
		{
			dw = WaitForSingleObject(child->m_thread, INFINITE); mk_check(dw == WAIT_OBJECT_0);
			turbo_app_rw_child_rw_destroy(child);
			b = HeapFree(GetProcessHeap(), 0, child); mk_check(b);
			mk_close_dead_process_handles();
			turbo_app->m_children[turbo_app->m_active_child_idx] = NULL;
			idx = turbo_app->m_active_child_idx;
			turbo_app_rw_next(turbo_app);
			if(turbo_app->m_active_child_idx < idx)
			{
				turbo_app_rw_prev(turbo_app);
			}
		}
	}
}

static void turbo_app_rw_murder(turbo_app_t* const turbo_app)
{
	turbo_app_child_t* child;

	assert(turbo_app);

	if(turbo_app->m_active_child_idx != -1)
	{
		child = turbo_app->m_children[turbo_app->m_active_child_idx]; assert(child);
		if(!turbo_app_rw_child_ro_is_ded(child))
		{
			turbo_app_rw_child_rw_kill_and_drain(child);
		}
	}
}

static void turbo_app_rw_write_event(turbo_app_t* const turbo_app, KEY_EVENT_RECORD* const evt)
{
	turbo_app_child_t* child;
	char chr;
	BOOL b;
	DWORD written;

	assert(turbo_app);
	assert(evt);

	if(turbo_app->m_active_child_idx != -1)
	{
		child = turbo_app->m_children[turbo_app->m_active_child_idx]; assert(child);
		if(!turbo_app_rw_child_ro_is_ded(child))
		{
			chr = evt->uChar.AsciiChar;
			b = WriteFile(child->m_pipe_input_write, &chr, 1, &written, NULL); mk_check(b); mk_check(written == 1);
		}
	}
}

static void turbo_app_rw_on_event_key(turbo_app_t* const turbo_app, KEY_EVENT_RECORD* const evt)
{
	assert(turbo_app);
	assert(evt);

	if(false){}
	else if
	(
		(evt->bKeyDown) &&
		(
			((evt->dwControlKeyState & LEFT_CTRL_PRESSED) != 0) ||
			((evt->dwControlKeyState & RIGHT_CTRL_PRESSED) != 0) ||
			(false)
		) &&
		(evt->wVirtualKeyCode == 'W') &&
		(true)
	)
	{
		turbo_app->m_should_exit = true;
	}
	else if
	(
		(evt->bKeyDown) &&
		(
			((evt->dwControlKeyState & LEFT_CTRL_PRESSED) != 0) ||
			((evt->dwControlKeyState & RIGHT_CTRL_PRESSED) != 0) ||
			(false)
		) &&
		(evt->wVirtualKeyCode == 'U') &&
		(true)
	)
	{
		turbo_app_rw_reap(turbo_app);
	}
	else if
	(
		(evt->bKeyDown) &&
		(
			((evt->dwControlKeyState & LEFT_CTRL_PRESSED) != 0) ||
			((evt->dwControlKeyState & RIGHT_CTRL_PRESSED) != 0) ||
			(false)
		) &&
		(evt->wVirtualKeyCode == 'I') &&
		(true)
	)
	{
		turbo_app_rw_murder(turbo_app);
	}
	else if
	(
		(evt->bKeyDown) &&
		(
			((evt->dwControlKeyState & LEFT_CTRL_PRESSED) != 0) ||
			((evt->dwControlKeyState & RIGHT_CTRL_PRESSED) != 0) ||
			(false)
		) &&
		(evt->wVirtualKeyCode == 'O') &&
		(true)
	)
	{
		turbo_app_rw_prev(turbo_app);
	}
	else if
	(
		(evt->bKeyDown) &&
		(
			((evt->dwControlKeyState & LEFT_CTRL_PRESSED) != 0) ||
			((evt->dwControlKeyState & RIGHT_CTRL_PRESSED) != 0) ||
			(false)
		) &&
		(evt->wVirtualKeyCode == 'P') &&
		(true)
	)
	{
		turbo_app_rw_next(turbo_app);
	}
	else if
	(
		(evt->bKeyDown) &&
		(
			((evt->dwControlKeyState & LEFT_CTRL_PRESSED) != 0) ||
			((evt->dwControlKeyState & RIGHT_CTRL_PRESSED) != 0) ||
			(false)
		) &&
		(evt->wVirtualKeyCode == 'R') &&
		(true)
	)
	{
		turbo_app_rw_run_self(turbo_app);
	}
	else if
	(
		(evt->bKeyDown) &&
		(
			((evt->dwControlKeyState & LEFT_CTRL_PRESSED) != 0) ||
			((evt->dwControlKeyState & RIGHT_CTRL_PRESSED) != 0) ||
			(false)
		) &&
		(evt->wVirtualKeyCode == 'T') &&
		(true)
	)
	{
		turbo_app_rw_run_cmd(turbo_app);
	}
	else if(evt->bKeyDown && evt->uChar.AsciiChar >= 0x20 && evt->uChar.AsciiChar < 0x7f)
	{
		turbo_app_rw_write_event(turbo_app, evt);
	}
	else if(evt->bKeyDown && evt->uChar.AsciiChar == 0x08)
	{
		turbo_app_rw_write_event(turbo_app, evt);
	}
	else if(evt->bKeyDown && evt->uChar.AsciiChar == 0x0d)
	{
		turbo_app_rw_write_event(turbo_app, evt);
	}
}

static void turbo_app_rw_on_event_size(turbo_app_t* const turbo_app, WINDOW_BUFFER_SIZE_RECORD* const evt)
{
	BOOL b;
	CONSOLE_SCREEN_BUFFER_INFO screen_buffer_info;
	bool different;
	COORD coords;
	bool did_something;

	assert(turbo_app);
	assert(evt);

	(void)evt;
	b = GetConsoleScreenBufferInfo(turbo_app->m_screen_buffer, &screen_buffer_info); mk_check(b);
	different =
		turbo_app->m_screen_buffer_info.dwSize.X != screen_buffer_info.dwSize.X ||
		turbo_app->m_screen_buffer_info.dwSize.Y != screen_buffer_info.dwSize.Y;
	turbo_app->m_screen_buffer_info = screen_buffer_info;
	if(different)
	{
		coords.X = screen_buffer_info.dwSize.X;
		coords.Y = screen_buffer_info.dwSize.Y;
		did_something = true;
		while(did_something)
		{
			did_something = false;
			if(!did_something)
			{
				coords.Y -= 1;
				b = SetConsoleScreenBufferSize(turbo_app->m_screen_buffer, coords);
				if(b)
				{
					did_something = true;
				}
			}
			if(!did_something)
			{
				coords.X -= 1;
				b = SetConsoleScreenBufferSize(turbo_app->m_screen_buffer, coords);
				if(b)
				{
					did_something = true;
				}
			}
		}
		b = GetConsoleScreenBufferInfo(turbo_app->m_screen_buffer, &turbo_app->m_screen_buffer_info); mk_check(b);
	}
	turbo_app_rw_hide_cursor(turbo_app);
}

static void turbo_app_rw_on_event_menu(turbo_app_t* const turbo_app, MENU_EVENT_RECORD* const evt)
{
	assert(turbo_app);
	assert(evt);

	(void)turbo_app;
	(void)evt;
}

static void turbo_app_rw_on_event_focus(turbo_app_t* const turbo_app, FOCUS_EVENT_RECORD* const evt)
{
	assert(turbo_app);
	assert(evt);

	(void)turbo_app;
	(void)evt;
}

static void turbo_app_rw_on_event_general(turbo_app_t* const turbo_app, INPUT_RECORD* const evt)
{
	assert(turbo_app);
	assert(evt);

	switch(evt->EventType)
	{
		case KEY_EVENT:                turbo_app_rw_on_event_key  (turbo_app, &evt->Event.KeyEvent);              break;
		case WINDOW_BUFFER_SIZE_EVENT: turbo_app_rw_on_event_size (turbo_app, &evt->Event.WindowBufferSizeEvent); break;
		case MENU_EVENT:               turbo_app_rw_on_event_menu (turbo_app, &evt->Event.MenuEvent);             break;
		case FOCUS_EVENT:              turbo_app_rw_on_event_focus(turbo_app, &evt->Event.FocusEvent);            break;
		default: mk_check_todo(); break;
	}
}

static void turbo_app_rw_process_events(turbo_app_t* const turbo_app)
{
	DWORD n;
	DWORD i;
	INPUT_RECORD* evt;

	assert(turbo_app);

	n = turbo_app->m_events_cnt;
	for(i = 0; i != n; ++i)
	{
		evt = &turbo_app->m_events_buf[i];
		turbo_app_rw_on_event_general(turbo_app, evt);
	}
}

static void turbo_app_rw_child_scroll_one_if_needed(turbo_app_t* const turbo_app, turbo_app_child_t* const child)
{
	int n;
	int i;

	assert(turbo_app);
	assert(child);

	(void)turbo_app;
	if(child->m_cursor_pos.Y == child->m_size.Y)
	{
		child->m_cursor_pos.Y -= 1;
		memmove(&child->m_chars[0], &child->m_chars[child->m_size.X], child->m_size.Y * child->m_size.X * sizeof(child->m_chars[0]));
		memmove(&child->m_attrs[0], &child->m_attrs[child->m_size.X], child->m_size.Y * child->m_size.X * sizeof(child->m_attrs[0]));
		n = child->m_size.X;
		for(i = 0; i != n; ++i)
		{
			child->m_chars[(child->m_size.Y - 1) * child->m_size.X + i] = L' ';
			child->m_attrs[(child->m_size.Y - 1) * child->m_size.X + i] = (FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE) | (0);
		}
	}
}

static void turbo_app_rw_child_on_cmd_bracketed_paste_on(turbo_app_t* const turbo_app, turbo_app_child_t* const child)
{
	assert(turbo_app);
	assert(child);

	(void)turbo_app;
	(void)child;
}

static void turbo_app_rw_child_crlf(turbo_app_t* const turbo_app, turbo_app_child_t* const child)
{
	assert(turbo_app);
	assert(child);

	(void)turbo_app;
	child->m_cursor_pos.X = 0;
	child->m_cursor_pos.Y += 1;
	turbo_app_rw_child_scroll_one_if_needed(turbo_app, child);
}

static void turbo_app_rw_child_cr(turbo_app_t* const turbo_app, turbo_app_child_t* const child)
{
	assert(turbo_app);
	assert(child);

	(void)turbo_app;
	child->m_cursor_pos.X = 0;
}

static void turbo_app_rw_child_lf(turbo_app_t* const turbo_app, turbo_app_child_t* const child)
{
	assert(turbo_app);
	assert(child);

	(void)turbo_app;
	child->m_cursor_pos.Y += 1;
	turbo_app_rw_child_scroll_one_if_needed(turbo_app, child);
}

static void turbo_app_rw_child_bs(turbo_app_t* const turbo_app, turbo_app_child_t* const child)
{
	assert(turbo_app);
	assert(child);

	(void)turbo_app;
	child->m_cursor_pos.X -= 1;
	mk_check(child->m_cursor_pos.X >= 0);
	mk_check(child->m_cursor_pos.X < child->m_size.X);
	mk_check(child->m_cursor_pos.Y >= 0);
	mk_check(child->m_cursor_pos.Y < child->m_size.Y);
}

static void turbo_app_rw_child_set_background_color(turbo_app_t* const turbo_app, turbo_app_child_t* const child, unsigned char const color)
{
	unsigned char num;
	WORD w;

	assert(turbo_app);
	assert(child);
	assert(color >= '0');
	assert(color <= '9');

	(void)turbo_app;
	num = color - '0';
	w = 0;
	w = w | ((((num >> 0) & 1) == 0) ? (0) : (BACKGROUND_RED));
	w = w | ((((num >> 1) & 1) == 0) ? (0) : (BACKGROUND_GREEN));
	w = w | ((((num >> 2) & 1) == 0) ? (0) : (BACKGROUND_BLUE));
	w = w | ((((num >> 3) & 1) == 0) ? (0) : (BACKGROUND_INTENSITY));
	child->m_default_attrs &=~ (BACKGROUND_RED | BACKGROUND_GREEN | BACKGROUND_BLUE | BACKGROUND_INTENSITY);
	child->m_default_attrs |= w;
}

static void turbo_app_rw_child_move_cursor_to(turbo_app_t* const turbo_app, turbo_app_child_t* const child, unsigned char const row, unsigned char const col)
{
	unsigned char rrow;
	unsigned char ccol;

	assert(turbo_app);
	assert(child);
	assert(row >= '0');
	assert(row <= '9');
	assert(col >= '0');
	assert(col <= '9');

	(void)turbo_app;
	rrow = (row - '0') - 1;
	ccol = (col - '0') - 1;
	child->m_cursor_pos.Y = rrow;
	child->m_cursor_pos.X = ccol;
	mk_check(child->m_cursor_pos.X >= 0);
	mk_check(child->m_cursor_pos.X < child->m_size.X);
	mk_check(child->m_cursor_pos.Y >= 0);
	mk_check(child->m_cursor_pos.Y < child->m_size.Y);
}

static void turbo_app_rw_child_on_cmd_move_cursor_right_1(turbo_app_t* const turbo_app, turbo_app_child_t* const child, unsigned char const amount)
{
	unsigned char aamount;

	assert(turbo_app);
	assert(child);
	assert(amount >= '0');
	assert(amount <= '9');

	(void)turbo_app;
	aamount = amount - '0';
	child->m_cursor_pos.X += aamount;
	mk_check(child->m_cursor_pos.X >= 0);
	mk_check(child->m_cursor_pos.X < child->m_size.X);
	mk_check(child->m_cursor_pos.Y >= 0);
	mk_check(child->m_cursor_pos.Y < child->m_size.Y);
}

static void turbo_app_rw_child_set_foreground_color_1(turbo_app_t* const turbo_app, turbo_app_child_t* const child, unsigned char const color)
{
	unsigned char ccolor;
	WORD attr;

	assert(turbo_app);
	assert(child);
	assert(color >= '0');
	assert(color <= '9');

	(void)turbo_app;
	ccolor = color - '0';
	switch(ccolor)
	{
		case 8: attr = FOREGROUND_INTENSITY; break;
		default: mk_check_todo(); attr = 0; break;
	}
	child->m_default_attrs = child->m_default_attrs &~ (FOREGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
	child->m_default_attrs = child->m_default_attrs | attr;
}

static void turbo_app_rw_child_set_foreground_color_2(turbo_app_t* const turbo_app, turbo_app_child_t* const child, unsigned char const color_a, unsigned char const color_b)
{
	unsigned char ccolor_a;
	unsigned char ccolor_b;
	unsigned char ccolor;
	WORD attr;

	assert(turbo_app);
	assert(child);
	assert(color_a >= '0');
	assert(color_a <= '9');
	assert(color_b >= '0');
	assert(color_b <= '9');

	(void)turbo_app;
	ccolor_a = color_a - '0';
	ccolor_b = color_b - '0';
	ccolor = ccolor_a * 10 + ccolor_b;
	switch(ccolor)
	{
		case 11: attr = FOREGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_GREEN; break;
		case 14: attr = FOREGROUND_INTENSITY | FOREGROUND_GREEN | FOREGROUND_BLUE; break;
		case 15: attr = FOREGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE; break;
		default: mk_check_todo(); attr = 0; break;
	}
	child->m_default_attrs = child->m_default_attrs &~ (FOREGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
	child->m_default_attrs = child->m_default_attrs | attr;
}

static void turbo_app_rw_child_on_cmd_move_cursor_right_2(turbo_app_t* const turbo_app, turbo_app_child_t* const child, unsigned char const amount1, unsigned char const amount2)
{
	unsigned char aamount1;
	unsigned char aamount2;
	unsigned char aamount;

	assert(turbo_app);
	assert(child);
	assert(amount1 >= '0');
	assert(amount1 <= '9');
	assert(amount2 >= '0');
	assert(amount2 <= '9');

	(void)turbo_app;
	aamount1 = amount1 - '0';
	aamount2 = amount2 - '0';
	aamount = aamount1 * 10 + aamount2;
	child->m_cursor_pos.X += aamount;
	mk_check(child->m_cursor_pos.X >= 0);
	mk_check(child->m_cursor_pos.X < child->m_size.X);
	mk_check(child->m_cursor_pos.Y >= 0);
	mk_check(child->m_cursor_pos.Y < child->m_size.Y);
}

static void turbo_app_rw_child_move_cursor_to2(turbo_app_t* const turbo_app, turbo_app_child_t* const child, unsigned char const row1, unsigned char const row2, unsigned char const col)
{
	unsigned char rrow1;
	unsigned char rrow2;
	unsigned char rrow;
	unsigned char ccol;

	assert(turbo_app);
	assert(child);
	assert(row1 >= '0');
	assert(row1 <= '9');
	assert(row2 >= '0');
	assert(row2 <= '9');
	assert(col >= '0');
	assert(col <= '9');

	(void)turbo_app;
	rrow1 = row1 - '0';
	rrow2 = row2 - '0';
	rrow = (rrow1 * 10 + rrow2) - 1;
	ccol = (col - '0') - 1;
	child->m_cursor_pos.Y = rrow;
	child->m_cursor_pos.X = ccol;
	mk_check(child->m_cursor_pos.X >= 0);
	mk_check(child->m_cursor_pos.X < child->m_size.X);
	mk_check(child->m_cursor_pos.Y >= 0);
	mk_check(child->m_cursor_pos.Y < child->m_size.Y);
}

static void turbo_app_rw_child_move_cursor_to22(turbo_app_t* const turbo_app, turbo_app_child_t* const child, unsigned char const row1, unsigned char const row2, unsigned char const col1, unsigned char const col2)
{
	unsigned char rrow1;
	unsigned char rrow2;
	unsigned char ccol1;
	unsigned char ccol2;

	assert(turbo_app);
	assert(child);
	assert(row1 >= '0');
	assert(row1 <= '9');
	assert(row2 >= '0');
	assert(row2 <= '9');
	assert(col1 >= '0');
	assert(col1 <= '9');
	assert(col2 >= '0');
	assert(col2 <= '9');

	(void)turbo_app;
	rrow1 = row1 - '0';
	rrow2 = row2 - '0';
	ccol1 = col1 - '0';
	ccol2 = col2 - '0';
	child->m_cursor_pos.Y = (rrow1 * 10 + rrow2) - 1;
	child->m_cursor_pos.X = (ccol1 * 10 + ccol2) - 1;
	mk_check(child->m_cursor_pos.X >= 0);
	mk_check(child->m_cursor_pos.X < child->m_size.X);
	mk_check(child->m_cursor_pos.Y >= 0);
	mk_check(child->m_cursor_pos.Y < child->m_size.Y);
}

static void turbo_app_rw_child_on_cmd_erase2(turbo_app_t* const turbo_app, turbo_app_child_t* const child, unsigned char const amount1, unsigned char const amount2)
{
	unsigned char aamount1;
	unsigned char aamount2;
	unsigned char aamount;
	int idx;
	int n;
	int i;

	assert(turbo_app);
	assert(child);
	assert(amount1 >= '0');
	assert(amount1 <= '9');
	assert(amount2 >= '0');
	assert(amount2 <= '9');

	(void)turbo_app;
	aamount1 = amount1 - '0';
	aamount2 = amount2 - '0';
	aamount = aamount1 * 10 + aamount2;
	mk_check(aamount <= child->m_size.X);
	idx = child->m_cursor_pos.Y * child->m_size.X + child->m_cursor_pos.X;
	n = aamount;
	for(i = 0; i != n; ++i)
	{
		child->m_chars[idx + i] = L' ';
	}
	mk_check(child->m_cursor_pos.X >= 0);
	mk_check(child->m_cursor_pos.X < child->m_size.X);
	mk_check(child->m_cursor_pos.Y >= 0);
	mk_check(child->m_cursor_pos.Y < child->m_size.Y);
}

static void turbo_app_rw_child_move_cursor_home(turbo_app_t* const turbo_app, turbo_app_child_t* const child)
{
	assert(turbo_app);
	assert(child);

	(void)turbo_app;
	child->m_cursor_pos.X = 0;
	child->m_cursor_pos.Y = 0;
}

static void turbo_app_rw_child_on_erase_in_line(turbo_app_t* const turbo_app, turbo_app_child_t* const child)
{
	assert(turbo_app);
	assert(child);

	(void)turbo_app;
	(void)child;
}

static void turbo_app_rw_child_make_cursor_visible(turbo_app_t* const turbo_app, turbo_app_child_t* const child)
{
	assert(turbo_app);
	assert(child);

	(void)turbo_app;
	child->m_cursor_visible = true;
}

static void turbo_app_rw_child_make_cursor_invisible(turbo_app_t* const turbo_app, turbo_app_child_t* const child)
{
	assert(turbo_app);
	assert(child);

	(void)turbo_app;
	child->m_cursor_visible = false;
}

static void turbo_app_rw_child_put_char(turbo_app_t* const turbo_app, turbo_app_child_t* const child, unsigned char const* const buf, int const len)
{
	wchar_t wchr;
	int idx;

	assert(turbo_app);
	assert(child);
	assert(buf);
	assert(len >= 1);
	assert(len <= 4);

	(void)turbo_app;
	if(len == 1)
	{
		wchr = ((wchar_t)(buf[0]));
	}
	else if(len == 2)
	{
		wchr = ((wchar_t)(
			((((unsigned short)(buf[0])) & 0x1f) << 6) |
			((((unsigned short)(buf[1])) & 0x3f) << 0) |
			0));
	}
	else if(len == 3)
	{
		wchr = ((wchar_t)(
			((((unsigned short)(buf[0])) & 0x0f) << 12) |
			((((unsigned short)(buf[1])) & 0x3f) <<  6) |
			((((unsigned short)(buf[2])) & 0x3f) <<  0) |
			0));
	}
	else
	{
		mk_check_todo();
	}
	if(child->m_cursor_pos.X == child->m_size.X)
	{
		child->m_cursor_pos.X = 0;
		child->m_cursor_pos.Y += 1;
		turbo_app_rw_child_scroll_one_if_needed(turbo_app, child);
	}
	idx = child->m_cursor_pos.Y * child->m_size.X + child->m_cursor_pos.X;
	child->m_chars[idx] = wchr;
	child->m_attrs[idx] = child->m_default_attrs;
	child->m_cursor_pos.X += 1;
}

static bool turbo_app_rw_child_ro_matches(turbo_app_t* const turbo_app, turbo_app_child_t* const child, unsigned char const** const ptr, int* const len, char const* const str_buf, int const str_len)
{
	bool matches;
	int n;
	int i;

	assert(turbo_app);
	assert(child);
	assert(ptr);
	assert(len);
	assert(*ptr);
	assert(*len >= 0);
	assert(str_buf);
	assert(str_len >= 1);

	(void)turbo_app;
	(void)child;
	matches = false;
	if(*ptr && *len >= str_len)
	{
		n = str_len;
		for(i = 0; i != n; ++i)
		{
			if
			(!(
				((*ptr)[i] == ((unsigned char)(str_buf[i]))) ||
				(str_buf[i] == '#' && (*ptr)[i] >= ((unsigned char)('0')) && (*ptr)[i] <= ((unsigned char)('9')))
			))
			{
				break;
			}
		}
		matches = i == n;
		if(matches)
		{
			*ptr = *ptr + str_len;
			*len = *len - str_len;
		}
	}
	return matches;
}

static void turbo_app_rw_child_rw_process_inputs(turbo_app_t* const turbo_app, turbo_app_child_t* const child)
{
	int input_len;
	unsigned char input_buf[mk_countof(child->m_input_buf)];
	int rem;
	unsigned char const* ptr;

	assert(turbo_app);
	assert(child);

	EnterCriticalSection(&child->m_cs);
	input_len = child->m_input_len;
	memcpy(&input_buf[0], &child->m_input_buf[0], child->m_input_len);
	child->m_input_len = 0;
	LeaveCriticalSection(&child->m_cs);
	WakeConditionVariable(&child->m_cv);
	rem = input_len;
	ptr = &input_buf[0];
	while(rem != 0)
	{
		if(false){}
		else if(turbo_app_rw_child_ro_matches(turbo_app, child, &ptr, &rem, mk_strlit("\x1b[##;##H"))){ turbo_app_rw_child_move_cursor_to22(turbo_app, child, ptr[2 - 8], ptr[3 - 8], ptr[5 - 8], ptr[6 - 8]); }
		else if(turbo_app_rw_child_ro_matches(turbo_app, child, &ptr, &rem, mk_strlit("\x1b[##;#H"))){ turbo_app_rw_child_move_cursor_to2(turbo_app, child, ptr[2 - 7], ptr[3 - 7], ptr[5 - 7]); }
		else if(turbo_app_rw_child_ro_matches(turbo_app, child, &ptr, &rem, mk_strlit("\x1b[##C"))){ turbo_app_rw_child_on_cmd_move_cursor_right_2(turbo_app, child, ptr[2 - 5], ptr[3 - 5]); }
		else if(turbo_app_rw_child_ro_matches(turbo_app, child, &ptr, &rem, mk_strlit("\x1b[##X"))){ turbo_app_rw_child_on_cmd_erase2(turbo_app, child, ptr[2 - 5], ptr[3 - 5]); }
		else if(turbo_app_rw_child_ro_matches(turbo_app, child, &ptr, &rem, mk_strlit("\x1b[#;#H"))){ turbo_app_rw_child_move_cursor_to(turbo_app, child, ptr[2 - 6], ptr[4 - 6]); }
		else if(turbo_app_rw_child_ro_matches(turbo_app, child, &ptr, &rem, mk_strlit("\x1b[#C"))){ turbo_app_rw_child_on_cmd_move_cursor_right_1(turbo_app, child, ptr[2 - 4]); }
		else if(turbo_app_rw_child_ro_matches(turbo_app, child, &ptr, &rem, mk_strlit("\x1b[2J"))){ turbo_app_rw_child_draw_erase(turbo_app, child); }
		else if(turbo_app_rw_child_ro_matches(turbo_app, child, &ptr, &rem, mk_strlit("\x1b[38;5;##m"))){ turbo_app_rw_child_set_foreground_color_2(turbo_app, child, ptr[7 - 10], ptr[8 - 10]); }
		else if(turbo_app_rw_child_ro_matches(turbo_app, child, &ptr, &rem, mk_strlit("\x1b[38;5;#m"))){ turbo_app_rw_child_set_foreground_color_1(turbo_app, child, ptr[7 - 9]); }
		else if(turbo_app_rw_child_ro_matches(turbo_app, child, &ptr, &rem, mk_strlit("\x1b[3J"))){ turbo_app_rw_child_on_erase_saved_lines(turbo_app, child); }
		else if(turbo_app_rw_child_ro_matches(turbo_app, child, &ptr, &rem, mk_strlit("\x1b[48;5;#"))){ turbo_app_rw_child_set_background_color(turbo_app, child, ptr[7 - 8]); }
		else if(turbo_app_rw_child_ro_matches(turbo_app, child, &ptr, &rem, mk_strlit("\x1b[?2004h"))){ turbo_app_rw_child_on_cmd_bracketed_paste_on(turbo_app, child); }
		else if(turbo_app_rw_child_ro_matches(turbo_app, child, &ptr, &rem, mk_strlit("\x1b[?25h"))){ turbo_app_rw_child_make_cursor_visible(turbo_app, child); }
		else if(turbo_app_rw_child_ro_matches(turbo_app, child, &ptr, &rem, mk_strlit("\x1b[?25l"))){ turbo_app_rw_child_make_cursor_invisible(turbo_app, child); }
		else if(turbo_app_rw_child_ro_matches(turbo_app, child, &ptr, &rem, mk_strlit("\x1b[H"))){ turbo_app_rw_child_move_cursor_home(turbo_app, child); }
		else if(turbo_app_rw_child_ro_matches(turbo_app, child, &ptr, &rem, mk_strlit("\x1b[K"))){ turbo_app_rw_child_on_erase_in_line(turbo_app, child); }
		else if(turbo_app_rw_child_ro_matches(turbo_app, child, &ptr, &rem, mk_strlit("\x1b[m"))){ turbo_app_rw_child_on_cmd_reset(turbo_app, child); }
		else if(turbo_app_rw_child_ro_matches(turbo_app, child, &ptr, &rem, mk_strlit("\x1b]0;"))){ /* title */ while(rem >= 1 && ptr[0] != 0x07){ ++ptr; --rem; } mk_check(rem >= 1); mk_check(ptr[0] == 0x07); ptr += 1; rem -= 1; }
		else if(turbo_app_rw_child_ro_matches(turbo_app, child, &ptr, &rem, mk_strlit("\x0d\x0a"))){ turbo_app_rw_child_crlf(turbo_app, child); }
		else if(turbo_app_rw_child_ro_matches(turbo_app, child, &ptr, &rem, mk_strlit("\x08"))){ turbo_app_rw_child_bs(turbo_app, child); }
		else if(turbo_app_rw_child_ro_matches(turbo_app, child, &ptr, &rem, mk_strlit("\x0a"))){ turbo_app_rw_child_lf(turbo_app, child); }
		else if(turbo_app_rw_child_ro_matches(turbo_app, child, &ptr, &rem, mk_strlit("\x0d"))){ turbo_app_rw_child_cr(turbo_app, child); }
		else if(rem >= 1 && ptr[0] >= 0x00 && ptr[0] < 0x20){ mk_check_todo(); }
		else if(rem >= 1 && ptr[0] >= 0x20 && ptr[0] < 0x7f){ turbo_app_rw_child_put_char(turbo_app, child, ptr, 1); ptr += 1; rem -= 1; }
		else if(rem >= 2 && (ptr[0] & 0xe0) == 0xc0 && (ptr[1] & 0xc0) == 0x80){ turbo_app_rw_child_put_char(turbo_app, child, ptr, 2); ptr += 2; rem -= 2; }
		else if(rem >= 3 && (ptr[0] & 0xf0) == 0xe0 && (ptr[1] & 0xc0) == 0x80 && (ptr[2] & 0xc0) == 0x80){ turbo_app_rw_child_put_char(turbo_app, child, ptr, 3); ptr += 3; rem -= 3; }
		else{ mk_check_todo(); }
	}
}

static void turbo_app_rw_process_inputs(turbo_app_t* const turbo_app)
{
	int n;
	int i;
	turbo_app_child_t* child;

	assert(turbo_app);

	n = mk_countof(turbo_app->m_children);
	for(i = 0; i != n; ++i)
	{
		child = turbo_app->m_children[i];
		if(child)
		{
			turbo_app_rw_child_rw_process_inputs(turbo_app, child);
		}
	}
}

static void turbo_app_rw_on_child_ded(turbo_app_t* const turbo_app, turbo_app_child_t* const child)
{
	assert(turbo_app);
	assert(child);

	(void)turbo_app;
	ClosePseudoConsole(child->m_pseudo_console);
	child->m_pseudo_console = NULL;
}

static void turbo_app_rw_read_events(turbo_app_t* const turbo_app)
{
	HANDLE handles[2 + mk_countof(turbo_app->m_children)];
	int cnt;
	int n;
	int i;
	turbo_app_child_t* child;
	DWORD waited;
	BOOL b;

	assert(turbo_app);

	turbo_app->m_events_cnt = 0;
	handles[0] = turbo_app->m_screen_buffer;
	handles[1] = turbo_app->m_event;
	cnt = 0;
	n = mk_countof(turbo_app->m_children);
	for(i = 0; i != n; ++i)
	{
		child = turbo_app->m_children[i];
		if(child)
		{
			if(!turbo_app_rw_child_ro_is_ded(child))
			{
				handles[2 + cnt] = child->m_process;
				++cnt;
			}
		}
	}
	waited = WaitForMultipleObjects(2 + cnt, &handles[0], FALSE, 250); mk_check((waited >= WAIT_OBJECT_0 + 0 && waited <= WAIT_OBJECT_0 + 2 + cnt) || waited == WAIT_TIMEOUT);
	if(waited == WAIT_TIMEOUT)
	{
	}
	else if(waited == WAIT_OBJECT_0 + 0)
	{
		b = ReadConsoleInputW(turbo_app->m_std_input, &turbo_app->m_events_buf[0], mk_countof(turbo_app->m_events_buf), &turbo_app->m_events_cnt); mk_check(b);
	}
	else if(waited == WAIT_OBJECT_0 + 1)
	{
		b = ResetEvent(turbo_app->m_event); mk_check(b);
	}
	else if(waited >= WAIT_OBJECT_0 + 2 && waited < WAIT_OBJECT_0 + 2 + cnt)
	{
		n = mk_countof(turbo_app->m_children);
		for(i = 0; i != n; ++i)
		{
			child = turbo_app->m_children[i];
			if(child)
			{
				if(!turbo_app_rw_child_ro_is_ded(child))
				{
					if(child->m_process == handles[waited])
					{
						turbo_app_rw_on_child_ded(turbo_app, child);
						break;
					}
				}
			}
		}
	}
}

static void turbo_app_rw_init_std_handle_input(turbo_app_t* const turbo_app)
{
	HANDLE inh;

	assert(turbo_app);

	inh = GetStdHandle(STD_INPUT_HANDLE); mk_check(inh != INVALID_HANDLE_VALUE);
	turbo_app->m_std_input = inh;
}

static void turbo_app_rw_run(turbo_app_t* const turbo_app)
{
	assert(turbo_app);

	turbo_app_rw_construct(turbo_app);
	turbo_app_rw_init_std_handle_input(turbo_app);
	if(turbo_app->m_std_input)
	{
		turbo_app_rw_screen_enter(turbo_app);
		turbo_app_rw_hide_cursor(turbo_app);
		turbo_app_rw_register_ctrlc(turbo_app);
		while(!turbo_app->m_should_exit)
		{
			turbo_app_rw_process_inputs(turbo_app);
			turbo_app_rw_draw_all(turbo_app);
			turbo_app_rw_read_events(turbo_app);
			turbo_app_rw_process_events(turbo_app);
		}
		turbo_app_rw_unregister_ctrlc(turbo_app);
		turbo_app_rw_destroy(turbo_app);
		turbo_app_rw_screen_leave(turbo_app);
		mk_close_dead_process_handles();
	}
}


static turbo_app_t the_app;


int wmain(void)
{
	turbo_app_t* turbo_app;

	turbo_app = &the_app;
	pthe_app = turbo_app;
	turbo_app_rw_run(turbo_app);
}
