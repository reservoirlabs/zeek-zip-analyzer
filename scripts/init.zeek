module ZIP;

export {
    redef enum Log::ID += {LOG};

    ## Limits max recursion
    redef ZIP_Analyzer::MAX_DEPTH = 1;

    ## Limits space used by analyzer to fully inflate the archive
    redef ZIP_Analyzer::MAX_SPACE_USAGE = 100000; # in bytes

    ## This table controls what analyzers will be enabled for the recursive analysis by mapping mimetype to analyzer tag
    type string_dict: table[string] of string;
    global config_analyzers: string_dict &redef;

    ## ZIP Log record
    type Info: record {
        ts: time                     &log; ## Timestamp
        fid: string                  &log; ## Original ID assigned by file analysis manager
        content: string              &log; ## Names of compressed files
    valid: count                 &log;
        size: count                  &log;
        comp_size: count             &log;
        mtime: count                 &log;
        crc: count                   &log;
        comp_method: count           &log;
        encryption_method: count     &log;
        flags: count                 &log;
    };
}

event zeek_init() {
    Files::register_for_mime_type(Files::ANALYZER_ZIP, "application/zip");
    Log::create_stream(ZIP::LOG, [$columns=ZIP::Info, $path="zip"]);
}

event zip_file_header(f: fa_file, s: string, metadata: ZIP_Analyzer::Metadata) {
    # Logging the names of the files in the ZIP archive
    local rec: ZIP::Info = [$ts=network_time(),
                            $fid=f$id,
                            $content=s,
                $valid=metadata$valid,
                $size=metadata$size,
                $comp_size=metadata$comp_size,
                $mtime=metadata$mtime,
                $crc=metadata$crc,
                $comp_method=metadata$comp_method,
                $encryption_method=metadata$encryption_method,
                $flags=metadata$flags];
    Log::write(ZIP::LOG, rec);
}

