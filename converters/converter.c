#include <Windows.h>
#include <string.h>
#include <stdlib.h>
#include <wchar.h>

wchar_t* guid_to_string(const GUID *guid) {
    static wchar_t sguid[64]; // GUID has a fixed string length of 38 characters plus null terminator
    if (StringFromGUID2(guid, sguid, _countof(sguid))) {
        return sguid;
    } else {
        return L"";
    }
    free(guid);
}