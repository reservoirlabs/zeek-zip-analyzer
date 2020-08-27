module ZIP_Analyzer;

export {
    ##! This specifies the max amount of times we would want to recurse into a zip file
    const MAX_DEPTH: count = 3 &redef;

    ##! This limits the memory used by the analyzer to inflate a single file in bytes
    const MAX_SPACE_USAGE: count = 10000 &redef;
}

