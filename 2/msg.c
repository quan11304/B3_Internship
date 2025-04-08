#include <winuser.h>

void msg() {
    MessageBox(0,
        "You have been infected.",
        "Notice",
        0x00001030L);
    // MB_SYSTEMMODAL | MB_ICONWARNING | MB_OK
}