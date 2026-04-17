import HomeFooter from "../feature-plugins/home/footer"
import HomeTips from "../feature-plugins/home/tips"
import SidebarPulse from "../feature-plugins/sidebar/pulse"
import SidebarMcp from "../feature-plugins/sidebar/mcp"
import SidebarLsp from "../feature-plugins/sidebar/lsp"
import SidebarPlan from "../feature-plugins/sidebar/plan"
import SidebarActivity from "../feature-plugins/sidebar/activity"
import SidebarFiles from "../feature-plugins/sidebar/files"
import SidebarFooter from "../feature-plugins/sidebar/footer"
import PluginManager from "../feature-plugins/system/plugins"
import type { TuiPlugin, TuiPluginModule } from "@numasec/plugin/tui"

export type InternalTuiPlugin = TuiPluginModule & {
  id: string
  tui: TuiPlugin
}

export const INTERNAL_TUI_PLUGINS: InternalTuiPlugin[] = [
  HomeFooter,
  HomeTips,
  SidebarPulse,
  SidebarPlan,
  SidebarActivity,
  SidebarMcp,
  SidebarLsp,
  SidebarFiles,
  SidebarFooter,
  PluginManager,
]
