#include "cvault/persist.h"

cv_status cv_persist_replay(const char *directory, cv_hashtable *table) {
    (void)directory;
    (void)table;
    return CV_ERR_NOT_IMPLEMENTED;
}

cv_status cv_persist_snapshot(const char *directory, const cv_hashtable *table) {
    (void)directory;
    (void)table;
    /* POSIX fork and the Windows alternative belong behind a platform boundary. */
    return CV_ERR_NOT_IMPLEMENTED;
}
