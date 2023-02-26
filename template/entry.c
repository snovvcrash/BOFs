#include <windows.h>
#include "beacon.h"

VOID go(char* args, int alen) {
    datap parser;

    BeaconDataParse(&parser, args, alen);

    return;
}
