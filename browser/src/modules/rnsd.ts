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

  menu.register('settings', 'Settings', 10, [
    { id: 'reticulum', label: 'Reticulum', type: 'submenu', order: 30,
      children: [
        { id: 'reticulum.general', label: 'General', type: 'panel', order: 10,
          component: RnsdPanel },
      ],
    },
  ])

  menu.register('status', 'Status', 20, [
    { id: 'status.nodes', label: 'Show Nodes', type: 'action', order: 10,
      action: () => { nodesVisible.value = !nodesVisible.value } },
    { id: 'status.map', label: 'Show Map', type: 'action', order: 20,
      action: () => { mapVisible.value = !mapVisible.value } },
  ])
}
