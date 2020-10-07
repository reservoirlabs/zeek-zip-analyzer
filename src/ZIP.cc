#include <file_analysis/Manager.h>
#include "ZIP.h"

using namespace file_analysis;

ZIP::ZIP(RecordVal * args, File * file) : file_analysis::Analyzer(file_mgr->GetComponentTag("ZIP"), args, file) {
    zip_size = 0;

    TableVal* config_table = opt_internal_table("ZIP::config_analyzers");
    config_table_list = config_table->ConvertToList(TYPE_STRING);

    recursive_analyzers = new Analyzer*[config_table_list->Length()];

    for (int i = 0; i < config_table_list->Length(); i++) {
        const char* key = reinterpret_cast<const char*>(config_table_list->Index(i)->AsString()->Bytes());
        const char* tag = reinterpret_cast<const char*>(config_table->Lookup(config_table_list->Index(i), 1)->AsString()->Bytes());

        const string& tag_ref = string(tag);

        if (file_mgr->GetComponentTag(tag_ref) != file_analysis::Tag::Error) {
            recursive_analyzers[i] = file_mgr->InstantiateAnalyzer(file_mgr->GetComponentTag(tag_ref), args, file);
            recursive_analyzer_lookup.insert(std::pair<std::string, int>(key, i));

            fprintf(stderr, "%s analyzer found!", tag);
        } else {
            fprintf(stderr, "%s analyzer not found!", tag);
        }
    }
}

ZIP::~ZIP() {
    if (recursive_analyzers) {
        for(map<string,int>::iterator it = recursive_analyzer_lookup.begin(); it != recursive_analyzer_lookup.end(); ++it) {
            delete recursive_analyzers[it->second];
        }

        delete recursive_analyzers;
    }
}

/*
 * Invoked whenever bytes go missing. Analysis will almost never work properly if this happens
 *
 * @param offset    pointer to an array of incoming bytes
 * @param len       is the amount of incoming bytes
 * @returns boolean indicating if analysis is still valid
 */
bool ZIP::Undelivered(uint64 offset, uint64 len) {
    return false;
}

/*
 * Invoked whenever a new data block arrives
 *
 * @param data  pointer to an array of incoming bytes
 * @param len   is the amount of incoming bytes
 * @returns boolean indicating if analysis is still valid
 */
bool ZIP::DeliverStream(const u_char * data, uint64 len) {
    zip_data.append(reinterpret_cast<const char *>(data), len);
    zip_size = zip_size + len;
    return true;
}

/*
 * Invoked after the file has been fully reassembled 
 *
 * @returns boolean indicating if analysis is still valid
 */
bool ZIP::EndOfFile() {
    zip_error_t err;
    zip_t* zip_handle;

    zip_error_init(&err);

    zip_handle = ZIP::GetHandle(&zip_data[0], zip_size, &err);
    if (!zip_handle) {
        //Terminate safely without generating event
        return true;
    } 
    
    int mem_left = BifConst::ZIP_Analyzer::MAX_SPACE_USAGE;
    RecursiveAnalysis(zip_handle, &err, BifConst::ZIP_Analyzer::MAX_DEPTH, &mem_left);

    zip_discard(zip_handle);
    zip_error_fini(&err);
    return true;
}

/*
 * Extracts and analyzes compressed files recursively
 *
 * @param handle is the pointer to the struct provided by libzip for zip manipulation
 * @param error      will hold any possible error encountered in doing any zip operation
 * @param max_depth  specifies maximum recursive depth
 * @param space_left   is a pointer to how much space we are limiting the recursive extraction to use
 */
void ZIP::RecursiveAnalysis(zip_t* handle, zip_error_t* error, int max_depth, int* space_left) {
    if(CheckError(error) == 1 || max_depth == 0 || *space_left <= 0) {
        return; //done
    } else {
        int num_files = zip_get_num_entries(handle, ZIP_FL_UNCHANGED);

        int inflated_size;
        void* inflated_buf; 
        
        for (int i = 0; i < num_files && *space_left > 0; i++) {
            inflated_buf = ExtractFromIndex(handle, error, i, space_left, &inflated_size);
            if (inflated_buf) {
                RecordVal* info = new RecordVal(BifType::Record::ZIP_Analyzer::Info);
                info->Assign(0, new StringVal(inflated_size, static_cast<const char*>(inflated_buf)));
                info->Assign(1, zeek::val_mgr->Count(inflated_size));
                BifEvent::generate_zip_file_info((analyzer::Analyzer*)this, GetFile()->GetVal()->Ref(), info);

                string sig_match = file_mgr->DetectMIME(reinterpret_cast<const unsigned char*>(inflated_buf), inflated_size);

                if (!sig_match.length() == 0) {
                    if (supported_zips.find(sig_match) != supported_zips.end()) {
                        zip_t* inner_handle;
                        zip_error_t inner_error;

                        zip_error_init(&inner_error);
                        
                        inner_handle = GetHandle(inflated_buf, inflated_size, &inner_error);
                        if(inner_handle) 
                            RecursiveAnalysis(inner_handle, &inner_error, max_depth - 1, space_left);

                        zip_discard(inner_handle);
                        zip_error_fini(&inner_error);
                    } else {
                          for(map<string,int>::iterator it = recursive_analyzer_lookup.begin(); it != recursive_analyzer_lookup.end(); ++it) {
                             regex* pat =  new std::regex(it->first);
                             if (std::regex_match(sig_match, *pat)) {
                                 int analyzer_idx = it->second; 
			         recursive_analyzers[analyzer_idx]->DeliverStream(reinterpret_cast<const unsigned char*>(inflated_buf), inflated_size);
			         recursive_analyzers[analyzer_idx]->EndOfFile();
                             }
                             
                             delete pat;
                          }

                    }
                } else {
			// no signature detected
                } 

                free(inflated_buf);
            }
        }
    }
}

/*
 * Returns a pointer to a raw buffer of a decompressed file from a zip
 *
 * @param handle      is the pointer to the struct provided by libzip for zip manipulation
 * @param error       will hold any possible error encountered in doing any zip operation  
 * @param index       file index in zip archive
 * @param space_left  how many more bytes are allowed to be decompressed
 * @param size        this pointer is consumed and filled with the size of the decompressed file
 * @returns           pointer to raw buffer
 */
void* ZIP::ExtractFromIndex(zip_t* handle, zip_error_t* error, int index, int* space_left, int *size) {
    zip_stat_t sb;
    zip_file_t* inner_file;
    
    zip_stat_index(handle, index, ZIP_STAT_SIZE, &sb);
    inner_file = zip_fopen_index(handle, index, 0);

    *size = sb.size;

    if (CheckError(error) == 0 && (static_cast<const int>(*space_left - sb.size) > 0 && inner_file)) {
        void* ret = malloc(sb.size);
        *space_left = *space_left - sb.size;

        zip_fread(inner_file, ret, sb.size);
        zip_fclose(inner_file);

        return ret;
    }

    if (inner_file) {
        zip_fclose(inner_file);
    }
    
    return nullptr;
} 


/*
 * Takes in a zip file buffer and returns a handle to a zip_t struct for libzip manipulation
 *
 * @param buf     pointer to zip file buffer 
 * @param size    size of zip file in bytes
 * @param error   will hold any possible error encountered in doing any zip operation
 * @returns       handle to zip_t struct of zip file bufer
 */
zip_t* ZIP::GetHandle(void* buf, int size, zip_error_t* error) {
    //The 1 in this function means the buffer will be freed when no longer needed
    zip_source_t* zip_src = zip_source_buffer_create(buf, (zip_uint64_t) size, 0, error);
    if(CheckError(error) == 1) {
	fprintf(stderr, "could not create source buffer\n");
        return nullptr;
    }

    //The 0 here means no special flags
    zip_t* zip_handle = zip_open_from_source(zip_src, 0, error);
    if(CheckError(error) == 1) {
	fprintf(stderr, "could not open from source\n");
        return nullptr;
    }

    zip_stat_t sb;
    zip_source_stat(zip_src, &sb);
                
    RecordVal* metadata = new RecordVal(BifType::Record::ZIP_Analyzer::Metadata);
    metadata->Assign(0, zeek::val_mgr->Count(sb.valid)); 
    metadata->Assign(1, zeek::val_mgr->Count(sb.size));
    metadata->Assign(2, zeek::val_mgr->Count(sb.comp_size));
    metadata->Assign(3, zeek::val_mgr->Count(sb.mtime));
    metadata->Assign(4, zeek::val_mgr->Count(sb.crc));
    metadata->Assign(5, zeek::val_mgr->Count(sb.comp_method));
    metadata->Assign(6, zeek::val_mgr->Count(sb.encryption_method));
    metadata->Assign(7, zeek::val_mgr->Count(sb.flags));
    
    BifEvent::generate_zip_file_header((analyzer::Analyzer *)this,
            GetFile()->GetVal()->Ref(),
            new StringVal(ZIP::GetDirectoryListing(zip_handle)),
            metadata);

    //delete metadata;
    
    return zip_handle;
}

/*
 * Retrieves a list of file names from a zip file
 *
 * @param handle   is the pointer to the struct provided by libzip for zip manipulation
 * @returns        all file names in the zip delimited by space
 */
string ZIP::GetDirectoryListing(zip_t* handle) {
    string ret = "";
    
    int num_files = zip_get_num_entries(handle, ZIP_FL_UNCHANGED);
    for (int i = 0; i < num_files; i++) {
        ret = ret + "," + zip_get_name(handle, i, ZIP_FL_ENC_RAW);
    }

    return ret;
}

/*
 * Checks the zip error pointer for error handling purposes and may trigger an
 * error event in Bro
 *
 * @param handle   is the pointer to the struct provided by libzip for zip manipulation
 * @returns        an int representing error state
 */
int ZIP::CheckError(zip_error_t* error) {
    if(zip_error_code_zip(error) != 0) {
        BifEvent::generate_zip_error((analyzer::Analyzer *)this, GetFile()->GetVal()->Ref(), new StringVal(zip_error_strerror(error)));
        return 1;
    }
    return 0;
}

