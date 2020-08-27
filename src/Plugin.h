/* R-SCOPE RIGHTS */

#ifndef BRO_PLUGIN_ANALYZER_ZIP
#define BRO_PLUGIN_ANALYZER_ZIP

#include <plugin/Plugin.h>

namespace plugin {
    namespace Analyzer_ZIP {

    class Plugin : public ::plugin::Plugin {
        protected:
            // Overridden from plugin::Plugin.
            plugin::Configuration Configure() override;
    };

    extern Plugin plugin;
    }
}

#endif
