#include "ZIP.h"
#include "Plugin.h"
#include "file_analysis/Component.h"

namespace plugin { namespace Analyzer_ZIP { Plugin plugin; } }

using namespace plugin::Analyzer_ZIP;

plugin::Configuration Plugin::Configure() {
    AddComponent(new ::file_analysis::Component("ZIP", ::file_analysis::ZIP::Instantiate));
    plugin::Configuration config;
    config.name = "Zeek::ZIP";
    config.description = "a ZIP file analyzer for Zeek";
    config.version.major = 1;
    config.version.minor = 0;
#if BRO_PLUGIN_API_VERSION >= 7
    config.version.patch = 0;
#endif
    return config;
}
