#ifndef FILETYPE_WIC64_H
#define FILETYPE_WIC64_H
#include "filetypes.h"
#include "browsable_root.h"

class FileTypeWiC64 : public FileType {
public:
    explicit FileTypeWiC64(BrowsableDirEntry *) {}
    int fetch_context_items(IndexedList<Action *> &);
    static FileType *test_type(BrowsableDirEntry *);
    static SubsysResultCode_e execute_st(SubsysCommand *);
};
#endif
