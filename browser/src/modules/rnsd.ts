import { ref } from 'vue'
import { useMenuStore } from 'spangap-browser/stores/menu'
import { registerWindowMount } from 'spangap-browser/lib/windowMounts'
import RnsdPanel from '../panels/RnsdPanel.vue'
import MapWindow from '../panels/MapWindow.vue'
import NodesWindow from '../panels/NodesWindow.vue'

/* Visibility ref for the Status → Map floating window. Toggled by the menu
 * action below; <StraddleWindows/> binds the MapWindow component to it via the
 * mount registered below. Mirrors how spangap-browser/modules/advanced
 * exposes cliVisible/logVisible. */
export const mapVisible = ref(false)
export const nodesVisible = ref(false)

export function registerRnsd() {
  const menu = useMenuStore()

  registerWindowMount({ id: 'nodes', title: 'Reticulum Nodes',
                        component: NodesWindow, visible: nodesVisible })
  registerWindowMount({ id: 'map', title: 'Reticulum Map',
                        component: MapWindow, visible: mapVisible })

  /* Settings → Mesh Network → Reticulum / RNS (the lead item of the group). */
  menu.setMenu('settings/mesh', { label: 'Mesh Network', placement: 3 })
  menu.register('settings/mesh/general', 'Reticulum / RNS', { type: 'panel', component: RnsdPanel }, { placement: 1 })

  /* #if 0 — Show Nodes / Show Map removed from the menu; the NodesWindow /
   * MapWindow components and these visibility refs are kept for re-enabling. */
  if (false) {
    menu.register('status/nodes', 'Show Nodes',
      { type: 'action', action: () => { nodesVisible.value = !nodesVisible.value } })
    menu.register('status/map', 'Show Map',
      { type: 'action', action: () => { mapVisible.value = !mapVisible.value } })
  }
  /* #endif */
}
