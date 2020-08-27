module ZIP_Analyzer;

export {
    ## This type is used to encapsulate binary blobs 
    type Info: record {
        data: string;
        length: count;
    };

    type Metadata: record {
        valid: count;
        size: count;
        comp_size: count;
        mtime: count;
        crc: count;
        comp_method: count;
        encryption_method: count;
        flags: count;
    };
}

