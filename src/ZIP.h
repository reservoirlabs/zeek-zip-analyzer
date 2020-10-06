#include <file_analysis/Analyzer.h>
#include <file_analysis/File.h>

#include <plugin/Plugin.h>

#include <Val.h>
#include <string>
#include <unordered_set>
#include <regex>

#include "events.bif.h"
#include "analyzer_zip.bif.h"
#include "zip.h"

using namespace std;
	    
namespace file_analysis {

    class ZIP : public file_analysis::Analyzer {
        public:
            virtual ~ZIP();

            static file_analysis::Analyzer* Instantiate(RecordVal* args, File* file) {
                return new ZIP(args, file);
            }

            virtual bool Undelivered(uint64 offset, uint64 len);
            virtual bool DeliverStream(const u_char* data, uint64 len);
            virtual bool EndOfFile();
        protected:
            const unordered_set<string> supported_zips = 
            {"application/zip", 
             "application/epub+zip",
             "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
             "application/vnd.openxmlformats-officedocument.presentationml.presentation",
             "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"};


            string zip_data;
            int zip_size;

            Analyzer** recursive_analyzers;
            std::map<std::string, int> recursive_analyzer_lookup;
            
            ListVal* config_table_list;

            ZIP(RecordVal* args, File* file);            

            int CheckError(zip_error_t* error);
            zip_t* GetHandle(void* buf, int size, zip_error_t* error);
            string GetDirectoryListing(zip_t* handle);
            void RecursiveAnalysis(zip_t* handle, zip_error_t* error, int max_depth, int* space_left);
            void* ExtractFromIndex(zip_t* handle, zip_error_t* error, int index, int* space_left, int *size);
    };
}

