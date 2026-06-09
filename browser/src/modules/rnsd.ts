import { ref } from 'vue'
import { useMenuStore } from 'spangap-browser/stores/menu'
import RnsdPanel from '../panels/RnsdPanel.vue'

/* Visibility ref for the Status → Map floating window. Toggled by the menu
 * action below; MainLayout binds the MapWindow component to it. Mirrors
 * how spangap-browser/modules/advanced exposes cliVisible/logVisible. */
export const mapVisible = ref(false)
export const nodesVisible = ref(false)

export function registerRnsd() {
  const menu = useMenuStore()

  menu.register('settings/reticulum/general', 'General', { type: 'panel', component: RnsdPanel })

  menu.register('status/nodes', 'Show Nodes',
    { type: 'action', action: () => { nodesVisible.value = !nodesVisible.value } })
  menu.register('status/map', 'Show Map',
    { type: 'action', action: () => { mapVisible.value = !mapVisible.value } })
}
