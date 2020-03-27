#include "util.hpp"
#include <ctype.h>

using namespace std;

unsigned is_number(const string& s)
{
    unsigned i    = 0;
    unsigned base = 10;

    if (s.size() > 2 && s[0] == '0' && s[1] == 'x') {
        base = 16;
        i    = 2;
    }

    for (; i < s.size(); ++i) {
        if (base == 10 && !isdigit(s[i])) {
            base = 0;
            break;
        } else if (base == 16 && !isxdigit(s[i])) {
            base = 0;
            break;
        }
    }

    return base;
}
